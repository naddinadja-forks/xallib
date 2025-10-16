#include <asm-generic/errno.h>
#include <libxnvme.h>
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <khash.h>
#include <libxal.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xal.h>
#include <xal_odf.h>
#include <xal_pool.h>

struct xal_be_fiemap {
	struct xal_backend_base base;
	char *mountpoint;         ///< Path to mountpoint of dev
	int inotify_fd;           ///< File descriptor for inotify events
	void *inotify_inode_map;  ///< Map of inodes from inotify watch descriptors

	uint8_t _rsvd[16];
};
XAL_STATIC_ASSERT(sizeof(struct xal_be_fiemap) == XAL_BACKEND_SIZE, "Incorrect size");

KHASH_MAP_INIT_INT64(wd_to_inode, struct xal_inode *);

int
process_ino_fiemap(struct xal *xal, char *path, struct xal_inode *self);

int
xal_index_fiemap(struct xal *xal);

void
close_be_fiemap(void *be_ptr)
{
	struct xal_be_fiemap *be = (struct xal_be_fiemap *)be_ptr; 
	kh_wd_to_inode_t *inode_map = be->inotify_inode_map;

	free(be->mountpoint);

	if (inode_map) {
		kh_destroy(wd_to_inode, inode_map);
	}

	close(be->inotify_fd);

	return;
}

bool
_is_directory_member(char *name)
{
	bool is_self = strcmp(name, ".") == 0;
	bool is_parent = strcmp(name, "..") == 0;
	return !is_self && !is_parent;
}

int
retrieve_total_entries(char *path)
{
	struct stat sb;
	struct dirent *entry;
	DIR *d;
	int count, err;

	err = stat(path, &sb);
	if (err) {
		XAL_DEBUG("FAILED: stat(%s); errno(%d)", path, errno);
		return -errno;
	}

	if (!S_ISDIR(sb.st_mode)) {
		XAL_DEBUG("INFO: path(%s) is not a directory", path);
		return 0;
	}

	d = opendir(path);
	if (!d) {
		XAL_DEBUG("FAILED: xal_pool_claim_inodes(); errno(%d)", errno);
		return -errno;
	}

	count = 0;
	entry = readdir(d);
	while (entry) {
		if (!_is_directory_member(entry->d_name)) {
			entry = readdir(d);
			continue;
		}

		count += 1;
		if (entry->d_type == DT_DIR) {
			char subpath[strlen(path) + 1 + strlen(entry->d_name) + 1];
			int children;

			snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
			children = retrieve_total_entries(subpath);

			if (children < 0) {
				return -1;
			}

			count += children;
		}
		entry = readdir(d);
	}
	closedir(d);

	return count;
}

int
xal_open_be_fiemap(struct xal **xal, char *mountpoint)
{
	struct xal *cand;
	struct stat sb;
	struct xal_be_fiemap *be;
	int nallocated, err;

	if (!mountpoint) {
		XAL_DEBUG("FAILED: No mountpoint given");
		return -EINVAL;
	}

	cand = calloc(1, sizeof(*cand));
	if (!cand) {
		XAL_DEBUG("FAILED: calloc()");
		return -errno;
	}

	be = (struct xal_be_fiemap *)&cand->be;

	be->base.type = XAL_BACKEND_FIEMAP;
	be->base.close = close_be_fiemap;
	be->base.index = xal_index_fiemap;

	be->mountpoint = calloc(strlen(mountpoint), sizeof(char));
	if (!be->mountpoint) {
		XAL_DEBUG("FAILED: calloc(); errno(%d)", errno);
		err = -errno;
		goto failed;
	}

	strcpy(be->mountpoint, mountpoint);

	be->inotify_fd = inotify_init1(IN_NONBLOCK);
	if (be->inotify_fd < 0) {
		XAL_DEBUG("FAILED: inotify_init1(); errno(%d)", errno);
		err = -errno;
		goto failed;
	}

	be->inotify_inode_map = kh_init(wd_to_inode);
	if (!be->inotify_inode_map) {
		XAL_DEBUG("FAILED: kh_init()");
		err = -EINVAL;
		goto failed;
	}

	nallocated = retrieve_total_entries(be->mountpoint);
	if (nallocated < 0) {
		XAL_DEBUG("Failed: retrieve_total_entries()");
		err = nallocated;
		goto failed;
	}

	err = stat(be->mountpoint, &sb);
	if (err) {
		XAL_DEBUG("FAILED: stat(%s); errno(%d)", be->mountpoint, errno);
		err = -errno;
		goto failed;
	}

	cand->sb.blocksize = sb.st_blksize;
	cand->sb.rootino = sb.st_ino;
	cand->sb.agblocks = 1; // To calculcate the on-disk offsets correctly

	err =
	    xal_pool_map(&cand->inodes, 40000000UL, nallocated, sizeof(struct xal_inode));
	if (err) {
		XAL_DEBUG("FAILED: xal_pool_map(inodes); err(%d)", err);
		goto failed;
	}

	err =
	    xal_pool_map(&cand->extents, 40000000UL, nallocated, sizeof(struct xal_extent));
	if (err) {
		XAL_DEBUG("FAILED: xal_pool_map(extents); err(%d)", err);
		goto failed;
	}

	*xal = cand; // All is good; promote the candidate

	return 0;

failed:
	xal_close(cand);

	return err;
}

int
process_inode_dir_mounted_extents(struct xal *xal, char *path, struct xal_inode *inode)
{
	struct xal_be_fiemap *be = (struct xal_be_fiemap *)&xal->be;
	khash_t(wd_to_inode) *inode_map = be->inotify_inode_map;
	struct dirent *entry;
	DIR *d;
	uint32_t mask = IN_CREATE | IN_DELETE | IN_MOVE | IN_MODIFY | IN_ATTRIB;
	khiter_t iter;
	int wd, count, err;

	if (!xal_inode_is_dir(inode)) {
		XAL_DEBUG("FAILED: cannot process directory at path(%s) - not a directory", path);
		return -EINVAL;
	}

	wd = inotify_add_watch(be->inotify_fd, path, mask);
	if (wd < 0) {
		XAL_DEBUG("FAILED: inotify_add_watch(); errno(%d)", errno);
		return -errno;
	}

	iter = kh_put(wd_to_inode, inode_map, wd, &err);
	if (err < 0) {
		XAL_DEBUG("FAILED: kh_put()");
		return -EIO;
	}
	kh_value(inode_map, iter) = inode;

	/* Count number of directory entried, no processing yet */
	d = opendir(path);
	if (!d) {
		XAL_DEBUG("FAILED: xal_pool_claim_inodes(); errno(%d)", errno);
		return -errno;
	}

	count = 0;
	entry = readdir(d);
	while (entry) {
		if (!_is_directory_member(entry->d_name)) {
			entry = readdir(d);
			continue;
		}

		count += 1;
		entry = readdir(d);
	}
	closedir(d);

	err = xal_pool_claim_inodes(&xal->inodes, count, &inode->content.dentries.inodes);
	if (err) {
		XAL_DEBUG("FAILED: xal_pool_claim_inodes(); err(%d)", err);
		goto failed;
	}
	inode->content.dentries.count = 0;

	/* Actually process directory entries */
	d = opendir(path);
	if (!d) {
		XAL_DEBUG("FAILED: xal_pool_claim_inodes(); errno(%d)", errno);
		return -errno;
	}

	entry = readdir(d);
	while (entry) {
		if (!_is_directory_member(entry->d_name)) {
			entry = readdir(d);
			continue;
		}

		struct xal_inode *dentry = &inode->content.dentries.inodes[inode->content.dentries.count];

		strcpy(dentry->name, entry->d_name);
		dentry->namelen = strlen(dentry->name);
		dentry->parent = inode;

		inode->content.dentries.count += 1;

		char dentry_path[strlen(path) + 1 + strlen(dentry->name) + 1];
		snprintf(dentry_path, sizeof(dentry_path), "%s/%s", path, dentry->name);

		err = process_ino_fiemap(xal, dentry_path, dentry);
		if (err) {
			XAL_DEBUG("FAILED: process_ino_fiemap(); with path(%s)", dentry_path);
			goto failed;
		}
		entry = readdir(d);
	}

	closedir(d);

	return 0;

failed:
	if (d) {
		closedir(d);
	}

	return err;
}

/*
 * Take a pointer to a fiemap struct with an fm_extents array of size 0.
 * The ioctl sets the "mapped_extents" integer to the amount of extents
 * existing in the file descriptor, so we reallocate the fiemap to be of
 * the right size, and then run the ioctl again with "fm_extent_count" 
 * set to the right size too, such that all the extents are read into the
 * struct.
 */
int
read_fiemap(int fd, struct fiemap **fiemap_ptr)
{
	struct fiemap *fiemap = *fiemap_ptr;
	int extents_size;

	if (!fiemap) {
		return -EINVAL;
	}

	fiemap->fm_length = ~0;  // maximum number of bits
	fiemap->fm_extent_count = 0;  // read 0 extents

	if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
		XAL_DEBUG("FAILED: fiemap ioctl(); errno(%d)", errno);
		return -errno;
	}

	extents_size = sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents;

	fiemap = realloc(fiemap, sizeof(struct fiemap) + extents_size);
	if (!fiemap) {
		XAL_DEBUG("FAILED: fiemap realloc(); errno(%d)", errno);
		return -errno;
	}

	memset(fiemap->fm_extents, 0, extents_size);
	fiemap->fm_extent_count = fiemap->fm_mapped_extents;
	fiemap->fm_mapped_extents = 0;

	if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
		XAL_DEBUG("FAILED: fiemap ioctl(); errno(%d)", errno);
		return -errno;
	}

	*fiemap_ptr = fiemap;
	return 0;
}

int
process_inode_file_mounted_extents(struct xal *xal, char *path, struct xal_inode *inode)
{
	struct fiemap *fiemap;
	int fd, err = 0;

	if (!xal_inode_is_file(inode)) {
		XAL_DEBUG("FAILED: cannot process file at path(%s) - not a file", path);
		return -EINVAL;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		XAL_DEBUG("FAILED: open(%s); errno(%d)", path, errno);
		return -errno;
	}

	fiemap = malloc(sizeof(struct fiemap));
	if (!fiemap) {
		XAL_DEBUG("FAILED: malloc(); errno(%d)", errno);
		goto failed;
	}
	memset(fiemap, 0, sizeof(struct fiemap));

	err = read_fiemap(fd, &fiemap);
	if (err) {
		XAL_DEBUG("FAILED: read_fiemap()");
		goto failed;
	}

	if (fiemap->fm_mapped_extents > 0) {
		struct xal_extents *extents;

		err = xal_pool_claim_extents(&xal->extents, fiemap->fm_mapped_extents, &inode->content.extents.extent);
		if (err) {
			XAL_DEBUG("FAILED: xal_pool_claim_extents(); err(%d)", err);
			goto failed;
		}

		extents = &inode->content.extents;
		extents->count = fiemap->fm_mapped_extents;

		for (uint32_t i = 0; i < extents->count; i++) {
			struct xal_extent *extent = &extents->extent[i];

			extent->start_offset = fiemap->fm_extents[i].fe_logical / xal->sb.blocksize;
			extent->start_block  = fiemap->fm_extents[i].fe_physical / xal->sb.blocksize;
			extent->nblocks      = fiemap->fm_extents[i].fe_length / xal->sb.blocksize;
			extent->flag         = fiemap->fm_extents[i].fe_flags;
		}
	}

	free(fiemap);
	close(fd);

	return 0;

failed:
	free(fiemap);
	if (fd) {
		close(fd);
	}

	return err;
}

int
process_ino_fiemap(struct xal *xal, char *path, struct xal_inode *self)
{
	struct stat sb;
	int err;

	if (!path) {
		return -EINVAL;
	}

	err = stat(path, &sb);
	if (err) {
		XAL_DEBUG("FAILED: stat(%s); errno(%d)", path, errno);
		return -errno;
	}

	if (!self->ftype) {
		if S_ISDIR(sb.st_mode) {
			self->ftype = XAL_ODF_DIR3_FT_DIR;
		} else if (S_ISREG(sb.st_mode)) {
			self->ftype = XAL_ODF_DIR3_FT_REG_FILE;
		} else {
			XAL_DEBUG("FAILED: unsupported ftype");
			return -EINVAL;
		}
	}

	self->ino = sb.st_ino;
	self->size = sb.st_size;

	switch(self->ftype) {
		case XAL_ODF_DIR3_FT_DIR:
			err = process_inode_dir_mounted_extents(xal, path, self);
			if (err) {
				XAL_DEBUG("FAILED: process_inode_dir_mounted_extents():err(%d)", err);
				return err;
			}
			break;
		case XAL_ODF_DIR3_FT_REG_FILE:
			err = process_inode_file_mounted_extents(xal, path, self);
			if (err) {
				XAL_DEBUG("FAILED: process_inode_file_mounted_extents():err(%d)", err);
				return err;
			}
			break;
		default:
			XAL_DEBUG("FAILED: unsupported ftype");
			return -ENOSYS;
	}

	return 0;
}

int
xal_index_fiemap(struct xal *xal)
{
	struct xal_be_fiemap *be = (struct xal_be_fiemap *)&xal->be;
	int err;

	if (!strlen(be->mountpoint)) {
		XAL_DEBUG("FAILED: xal object has no mountpoint");
		return -EINVAL;
	}

	err = xal_pool_claim_inodes(&xal->inodes, 1, &xal->root);
	if (err) {
		XAL_DEBUG("FAILED: xal_pool_claim_inodes()");
		return err;
	}

	xal->root->ino = xal->sb.rootino;
	xal->root->ftype = XAL_ODF_DIR3_FT_DIR;
	xal->root->namelen = 0;
	xal->root->content.extents.count = 0;
	xal->root->content.dentries.count = 0;

	return process_ino_fiemap(xal, be->mountpoint, xal->root);
}

int
_inode_path(struct xal_be_fiemap *be, struct xal_inode *inode, char *path, int *idx)
{
	int wrtn, err;

	if (!inode) {
		return -1;
	}
	if (!inode->parent) {
		wrtn = snprintf(path + *idx, XAL_PATH_MAXLEN - *idx, "%s", be->mountpoint);
		*idx += wrtn;
		return 0;
	}

	err = _inode_path(be, inode->parent, path, idx);
	if (err) {
		XAL_DEBUG("FAILED: xal_inode_path()");
		return err;
	}

	if (path[*idx - 1] != '/')
		path[(*idx)++] = '/';

	wrtn = snprintf(path + *idx, XAL_PATH_MAXLEN - *idx, "%s", inode->name);
	*idx += wrtn;

	return 0;
}

void
get_inode_path(struct xal *xal, struct xal_inode *inode, char *path)
{
	struct xal_be_fiemap *be = (struct xal_be_fiemap *)&xal->be;
	int idx = 0;

	_inode_path(be, inode, path, &idx);
	path[idx] = '\0';
}

int
xal_validate(struct xal *xal)
{
	struct xal_be_fiemap *be = (struct xal_be_fiemap *)&xal->be;
	struct xal_inode *dir_inode, *inode;
	kh_wd_to_inode_t *inode_map = be->inotify_inode_map;
	char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	char path[XAL_PATH_MAXLEN];
	khiter_t iter;
    ssize_t len, i;
	int err;

	if (be->base.type != XAL_BACKEND_FIEMAP) {
		XAL_DEBUG("SKIPPED: Backend must be FIEMAP")
		return 0;
	}

	if (xal->dirty) {
		XAL_DEBUG("INFO: Breaking changes to the file system has been found before.");
		return 1;
	}

	len = read(be->inotify_fd, buf, sizeof buf);
	while (len > 0) {
		int wd;
		i = 0;

		while (i < len) {
			struct inotify_event *event = (struct inotify_event *)&buf[i];
			inode = NULL;  // reset the pointer to the inode

			if (event->mask & (IN_MODIFY | IN_ATTRIB)) {
				wd = event->wd;

				iter = kh_get(wd_to_inode, inode_map, wd);
				if (iter == kh_end(inode_map)) {
					XAL_DEBUG("FAILED: kh_get(%d)", wd);
					return -EINVAL;
				}

				XAL_DEBUG("INFO: found watch descriptor(%d)", wd);

				dir_inode = kh_val(inode_map, iter);
				if (!xal_inode_is_dir(dir_inode)) {
					XAL_DEBUG("FAILED: found inode is not a directory");
					return -EINVAL;
				}

				for (uint32_t j = 0; j < dir_inode->content.dentries.count; ++j) {
					struct xal_inode *child = &dir_inode->content.dentries.inodes[j];

					if (strcmp(child->name, event->name) == 0) {
						inode = child;
						break;
					}
				}

				if (!inode) {
					XAL_DEBUG("FAILED: could not find child with name(%s)", event->name);
					return -EINVAL;
				}

				get_inode_path(xal, inode, path);

				err = process_inode_file_mounted_extents(xal, path, inode);
				if (err) {
					XAL_DEBUG("FAILED: process_inode_file_mounted_extents(); err(%d)", err);
					return err;
				}
			} else {
				char mask_pp[64];
				int wrtn, idx = 0;

				if (event->mask & IN_CREATE) {
					wrtn = snprintf(mask_pp + idx, 64 - idx, "%s", " IN_CREATE");
					idx += wrtn;
				}
				if (event->mask & IN_DELETE) {
					wrtn = snprintf(mask_pp + idx, 64 - idx, "%s", " IN_DELETE");
					idx += wrtn;
				}
				if (event->mask & IN_MOVE) {
					wrtn = snprintf(mask_pp + idx, 64 - idx, "%s", " IN_MOVE");
					idx += wrtn;
				}
				if (event->mask & IN_ISDIR) {
					wrtn = snprintf(mask_pp + idx, 64 - idx, "%s", " IN_ISDIR");
					idx += wrtn;
				}

				XAL_DEBUG("INFO: File system has changed, event mask:%s", mask_pp);
				xal->dirty = true;

				return 1;
			}

			i += sizeof(struct inotify_event) + event->len;
		}

		len = read(be->inotify_fd, buf, sizeof buf);
	}

	return 0;
}
