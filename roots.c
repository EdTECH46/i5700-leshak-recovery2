/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mtdutils/mtdutils.h"
#include "mtdutils/mounts.h"
#include "minzip/Zip.h"
#include "roots.h"
#include "common.h"

// Only check for ext2/3/4 on the first run or when needed
static int check_fstype = 1;


/* Canonical pointers.
xxx may just want to use enums
 */
static const char g_mtd_device[] = "@\0g_mtd_device";
static const char g_raw[] = "@\0g_raw\0";
static const char g_package_file[] = "@\0g_package_file";
static char sys_fs[] = "auto\0";
static char data_fs[] = "auto\0";
static char cache_fs[] = "auto\0";

static RootInfo g_roots[] = {
    { "BOOT:", g_mtd_device, NULL, "boot", NULL, g_raw },
    { "SYSTEM:", "/dev/stl6", NULL, "system", "/system", sys_fs },
    { "DATA:",  "/dev/stl5", NULL, "userdata", "/data", data_fs },
    { "CACHE:", "/dev/stl7", NULL, "cache", "/cache", cache_fs },
    { "PACKAGE:", NULL, NULL, NULL, NULL, g_package_file },
    { "RECOVERY:", g_mtd_device, NULL, "recovery", "/", g_raw },
    { "SDCARD:", "/dev/block/mmcblk0p1", "/dev/block/mmcblk0", NULL, "/sdcard", "vfat\0" },
    { "TMP:", NULL, NULL, NULL, "/tmp", NULL },
};
#define NUM_ROOTS (sizeof(g_roots) / sizeof(g_roots[0]))


// TODO: for SDCARD:, try /dev/block/mmcblk0 if mmcblk0p1 fails

void recheck() {
	check_fstype=1;
}

static int
internal_root_mounted(const RootInfo *info)
{
    if (info->mount_point == NULL) {
        return -1;
    }
//xxx if TMP: (or similar) just say "yes"

    /* See if this root is already mounted.
     */
    int ret = scan_mounted_volumes();
    if (ret < 0) {
        return ret;
    }
    const MountedVolume *volume;
    volume = find_mounted_volume_by_mount_point(info->mount_point);
    if (volume != NULL) {
        /* It's already mounted.
         */
        return 0;
    }
    return -1;
}

static void check_fs() {
	LOGI("Checking FS types\n");
	int i;
	RootInfo *info;
       for (i = 1 ;i < 4 ;i++){
          info = &g_roots[i];
		  if(!chdir(info->mount_point)){
       	    mkdir(info->mount_point, 0755);  // in case it doesn't already exist
          } else chdir("/");
          if ( !strncmp(info->device,"/sdcard/",8) ) {
			  strcpy(info->filesystem,"ext4");
		  } else {		  
			  memset(info->filesystem,0,5);
			  if ( !mount(info->device, info->mount_point, "ext2", MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NODIRATIME, NULL)) memcpy(info->filesystem,"ext2\0",5);
			  else if ( !mount(info->device, info->mount_point, "ext4", MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NODIRATIME, NULL)) memcpy(info->filesystem,"ext4\0",5);
			  else memcpy(info->filesystem,"rfs\0",4);	 
		  }
       }
 }

static const RootInfo *
get_root_info_for_path(const char *root_path)
{
    const char *c;

    /* Find the first colon.
     */
    c = root_path;
    while (*c != '\0' && *c != ':') {
        c++;
    }
    if (*c == '\0') {
        return NULL;
    }
    size_t len = c - root_path + 1;
    size_t i;
    
    RootInfo *info;
    MountedVolume *volume;

    if (check_fstype) {
       check_fs();
    check_fstype = 0;
    }

    for (i = 0; i < NUM_ROOTS; i++) {
        info = &g_roots[i];
        if (strncmp(info->name, root_path, len) == 0) {
            LOGI("%s is the root\n",info->name);
            return info;
       }
    }
    //LOGE("Root Path <%s> not found\n",root_path);
    return NULL;
}

RootInfo * get_info(const char *root_path)
{
    const char *c;

    /* Find the first colon.
     */
    c = root_path;
    while (*c != '\0' && *c != ':') {
        c++;
    }
    if (*c == '\0') {
        return NULL;
    }
    size_t len = c - root_path + 1;
    size_t i;
    
    RootInfo *info;
    MountedVolume *volume;

    if (check_fstype) {
       check_fs();
    check_fstype = 0;
    }

    for (i = 0; i < NUM_ROOTS; i++) {
        info = &g_roots[i];
        if (strncmp(info->name, root_path, len) == 0) {
            LOGI("%s is the root\n",info->name);
            return info;
       }
    }
    //LOGE("Root Path <%s> not found\n",root_path);
    return NULL;
}

const char *
get_fs_type(const char *root_path)
{
   get_root_info_for_path("SYSTEM:"); 

   const char *c;

    /* Find the first colon.
     */
    c = root_path;
    while (*c != '\0' && *c != ':') {
        c++;
    }
    if (*c == '\0') {
        return NULL;
    }
    size_t len = c - root_path + 1;
    size_t i;

    RootInfo *info;

    for (i = 0; i < NUM_ROOTS; i++) {
        info = &g_roots[i];
        if (strncmp(info->name, root_path, len) == 0) {
            return info->filesystem;
       }
    }
    return "Error !";
}

static const ZipArchive *g_package = NULL;
static char *g_package_path = NULL;

int
register_package_root(const ZipArchive *package, const char *package_path)
{
    if (package != NULL) {
        package_path = strdup(package_path);
        if (package_path == NULL) {
            return -1;
        }
        g_package_path = (char *)package_path;
    } else {
        free(g_package_path);
        g_package_path = NULL;
    }
    g_package = package;
    return 0;
}

int
is_package_root_path(const char *root_path)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    return info != NULL && info->filesystem == g_package_file;
}

const char *
translate_package_root_path(const char *root_path,
        char *out_buf, size_t out_buf_len, const ZipArchive **out_package)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL || info->filesystem != g_package_file) {
        return NULL;
    }

    /* Strip the package root off of the path.
     */
    size_t root_len = strlen(info->name);
    root_path += root_len;
    size_t root_path_len = strlen(root_path);

    if (out_buf_len < root_path_len + 1) {
        return NULL;
    }
    strcpy(out_buf, root_path);
    *out_package = g_package;
    return out_buf;
}

/* Takes a string like "SYSTEM:lib" and turns it into a string
 * like "/system/lib".  The translated path is put in out_buf,
 * and out_buf is returned if the translation succeeded.
 */
const char *
translate_root_path(const char *root_path, char *out_buf, size_t out_buf_len)
{
    if (out_buf_len < 1) {
        return NULL;
    }

    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL || info->mount_point == NULL) {
        return NULL;
    }

    /* Find the relative part of the non-root part of the path.
     */
    root_path += strlen(info->name);  // strip off the "root:"
    while (*root_path != '\0' && *root_path == '/') {
        root_path++;
    }

    size_t mp_len = strlen(info->mount_point);
    size_t rp_len = strlen(root_path);
    if (mp_len + 1 + rp_len + 1 > out_buf_len) {
        return NULL;
    }

    /* Glue the mount point to the relative part of the path.
     */
    memcpy(out_buf, info->mount_point, mp_len);
    if (out_buf[mp_len - 1] != '/') out_buf[mp_len++] = '/';

    memcpy(out_buf + mp_len, root_path, rp_len);
    out_buf[mp_len + rp_len] = '\0';

    return out_buf;
}

int
is_root_path_mounted(const char *root_path)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL) {
        return -1;
    }
    return internal_root_mounted(info) >= 0;
}

int
ensure_root_path_mounted(const char *root_path)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL) {
        return -1;
    }

    int ret = internal_root_mounted(info);
    if (ret >= 0) {
        /* It's already mounted.
         */
	LOGW("Already mounted [%s]\n", info->device);
        return 0;
    }

    /* It's not mounted.
     */
    LOGW("Not mounted [%s]\n", info->device);
    if (info->device == g_mtd_device) {
        if (info->partition_name == NULL) {
            return -1;
        }
//TODO: make the mtd stuff scan once when it needs to
        mtd_scan_partitions();
        const MtdPartition *partition;
        partition = mtd_find_partition_by_name(info->partition_name);
        if (partition == NULL) {
            return -1;
        }
        return mtd_mount_partition(partition, info->mount_point,
                info->filesystem, 0);
    }

    if (info->device == NULL || info->mount_point == NULL ||
        info->filesystem == NULL ||
        info->filesystem == g_raw ||
        info->filesystem == g_package_file) {
        return -1;
    }

    if (info->filesystem != NULL) {
        if(!chdir(info->mount_point)){
       	    mkdir(info->mount_point, 0755);  // in case it doesn't already exist
        }
        else {
            chdir("/");
        }
        //ui_print("%s %s\n",info->name,info->filesystem);
        if ( !(strncmp(info->device,"/sdcard/",8) ) ) {
			LOGI("Mounting %s as %s",info->name,"ext4 image");
			char *args[] = {"/xbin/mount", "-t", info->filesystem, "-o", "loop,rw,noatime,nodiratime,nosuid,nodev,data=ordered,barrier=1", info->device, info->mount_point, NULL};          
			execv("/xbin/mount", args);
			LOGE("E:Can't mount%s\n(%s)\n", info->device, strerror(errno));
	   } else if ( strncmp(info->filesystem,"rfs",3) != 0 ){
		   if ( !strncmp(info->filesystem,"ext2",4) ) {
			   //ui_print("ext2\n");
				LOGI("Mounting %s as %s",info->name,"ext2");
				if (mount(info->device, info->mount_point, info->filesystem, MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NODIRATIME, NULL)){
					LOGE("Can't mount %s\n(%s)\n", info->device, strerror(errno));
					return -1;
				}
			} else if ( !strncmp(info->filesystem,"ext4",4) ) {
				LOGI("Mounting %s as %s",info->name,"ext4");
				char *args[] = {"/xbin/mount", "-t", info->filesystem, "-o", "rw,noatime,nodiratime,nosuid,nodev,data=ordered,barrier=1", info->device, info->mount_point, NULL};          
				execv("/xbin/mount", args);
				LOGE("E:Can't mount%s\n(%s)\n", info->device, strerror(errno));
			} else if ( !strncmp(info->filesystem,"auto",4) ) {
				//ui_print("auto\n");
				LOGE("E:Can't detect FS. Mounting as auto\n");
				char *args[] = {"/xbin/mount", "-t", info->filesystem, info->device, info->mount_point, NULL};          
				execv("/xbin/mount", args);
				LOGE("E:Can't mount%s\n(%s)\n", info->device, strerror(errno));
			}
			else { //SD Card
				LOGI("Mounting %s as %s",info->name,info->filesystem);
				if (mount(info->device, info->mount_point, info->filesystem, MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NODIRATIME, NULL)){
					LOGE("Can't mount %s\n(%s)\n", info->device, strerror(errno));
					return -1;
				}
			}            
        } else {
           LOGI("Mounting %s as %s",info->name,"rfs");
           if (mount(info->device, info->mount_point, "rfs", MS_NODEV | MS_NOSUID, "codepage=utf8,xattr,check=no")){
	            if (info->device2 == NULL) {
	                LOGE("Can't mount %s\n(%s)\n", info->device, strerror(errno));
	                return -1;
	            } else if (mount(info->device2, info->mount_point, info->filesystem, MS_NOATIME | MS_NODEV | MS_NODIRATIME , NULL)) {
                   if(mount(info->device2, info->mount_point, "rfs", MS_NODEV | MS_NOSUID, "codepage=utf8,xattr,check=no")){
	                    LOGE("Can't mount %s (or %s)\n(%s)\n",
	                    info->device, info->device2, strerror(errno));
	                    return -1;
	            }
                }
            }
        }
    } else {
		LOGE("E:Can't detect FS. Mounting as auto\n");
		strcpy(info->filesystem,"auto");
		char *args[] = {"/xbin/mount", "-t", info->filesystem, info->device, info->mount_point, NULL};          
		execv("/xbin/mount", args);
		LOGE("E:Can't mount%s\n(%s)\n", info->device, strerror(errno));
	}
    return 0;
}

int
ensure_root_path_unmounted(const char *root_path)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL) {
        return -1;
    }
    if (info->mount_point == NULL) {
        /* This root can't be mounted, so by definition it isn't.
         */
        return 0;
    }
//xxx if TMP: (or similar) just return error

    /* See if this root is already mounted.
     */
    int ret = scan_mounted_volumes();
    if (ret < 0) {
        return ret;
    }
    const MountedVolume *volume;
    volume = find_mounted_volume_by_mount_point(info->mount_point);
    if (volume == NULL) {
        /* It's not mounted.
         */
        return 0;
    }

    return unmount_mounted_volume(volume);
}

const MtdPartition *
get_root_mtd_partition(const char *root_path)
{
    const RootInfo *info = get_root_info_for_path(root_path);
    if (info == NULL || info->device != g_mtd_device ||
            info->partition_name == NULL)
    {
        return NULL;
    }
    mtd_scan_partitions();
    return mtd_find_partition_by_name(info->partition_name);
}

int
format_root_device(const char *root)
{
    /* Be a little safer here; require that "root" is just
     * a device with no relative path after it.
     */
    const char *c = root;
    while (*c != '\0' && *c != ':') {
        c++;
    }
    if (c[0] != ':' || c[1] != '\0') {
        LOGW("format_root_device: bad root name \"%s\"\n", root);
        return -1;
    }

    const RootInfo *info = get_root_info_for_path(root);
    if (info == NULL || info->device == NULL) {
        LOGW("format_root_device: can't resolve \"%s\"\n", root);
        return -1;
    }
    if (info->mount_point != NULL) {
        /* Don't try to format a mounted device.
         */
        int ret = ensure_root_path_unmounted(root);
        if (ret < 0) {
            LOGW("format_root_device: can't unmount \"%s\"\n", root);
            return ret;
        }
    }

    if (info->filesystem != NULL) {
        pid_t pid = fork();
	 if (pid == 0) {
	     if (info->filesystem != NULL && strncmp(info->filesystem, "ext",3) == 0) {
                char fst[10];
                sprintf(fst,"-T %s",info->filesystem);
                //We should create /etc/mtab
					struct stat st;
					if(stat("/etc",&st)) {
						mkdir("/etc",0777);
					}
					FILE* f=fopen("/etc/mtab","w");
					if ( f != NULL ) fclose(f);
	         LOGW("format: %s as %s\n", info->device, fst);
                if (strncmp(info->filesystem, "ext4",4) == 0) {					
					///xbin/mke2fs -T ext4 -F -q -m 0 -b 4096 -O ^huge_file,extent /sdcard/cm6/data.img
                   char* args[] = {"/xbin/mke2fs", fst, "-F", "-q", "-m 0", "-b 4096", "-O ^huge_file,extent", info->device, NULL};
                   execv("/xbin/mke2fs", args);
                } else {
                   char* args[] = {"/xbin/mke2fs", fst, "-F", "-q", "-m 0", "-b 4096", info->device, NULL};
                   execv("/xbin/mke2fs", args);
                }
                LOGE("E:Can't run mke2fs format [%s]\n", strerror(errno));       
	     } 
	     else if (info->filesystem != NULL && strcmp(info->filesystem, "rfs")==0){
	          LOGW("format: %s as rfs\n", info->device);
                 char* args[] = {"/xbin/stl.format", info->device, NULL};
                 execv("/xbin/stl.format", args);
                 fprintf(stderr, "E:Can't run STL format [%s]\n", strerror(errno));
            }
         else {
			 //We couldn't detect FS, so formatting as default RFS
			 LOGW("Fallback format: %s as rfs\n", info->device);
                 char* args[] = {"/xbin/stl.format", info->device, NULL};
                 execv("/xbin/stl.format", args);
                 fprintf(stderr, "E:Can't run STL format [%s]\n", strerror(errno));
			}
        _exit(-1);
	 }
	 
        int status;

        while (waitpid(pid, &status, WNOHANG) == 0) {
            ui_print(".");
            sleep(1);
        }
        ui_print("\n");

        if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
            LOGW("format_root_device: can't erase \"%s\"\n", root);
	    return -1;
        }
	return 0;
    }

    /* Format the device.
     */
    if (info->device == g_mtd_device) {
        mtd_scan_partitions();
        const MtdPartition *partition;
        partition = mtd_find_partition_by_name(info->partition_name);
        if (partition == NULL) {
            LOGW("format_root_device: can't find mtd partition \"%s\"\n",
                    info->partition_name);
            return -1;
        }
        if (info->filesystem == g_raw || !strcmp(info->filesystem, "yaffs2")) {
            MtdWriteContext *write = mtd_write_partition(partition);
            if (write == NULL) {
                LOGW("format_root_device: can't open \"%s\"\n", root);
                return -1;
            } else if (mtd_erase_blocks(write, -1) == (off_t) -1) {
                LOGW("format_root_device: can't erase \"%s\"\n", root);
                mtd_write_close(write);
                return -1;
            } else if (mtd_write_close(write)) {
                LOGW("format_root_device: can't close \"%s\"\n", root);
                return -1;
            } else {
                return 0;
            }
        }
    }
//TODO: handle other device types (sdcard, etc.)
    LOGW("format_root_device: can't handle non-mtd device \"%s\"\n", root);
    return -1;
}
