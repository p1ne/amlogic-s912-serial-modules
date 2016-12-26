/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define DEBUG 1
#if DEBUG

#ifdef USE_LIBLOG
#define LOG_TAG "usbhost"
#include "utils/Log.h"

#define D LOGD
#else
#define D //
#endif

#else
#define D(...)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>

#include <linux/usbdevice_fs.h>
#include <asm/byteorder.h>

#include "usbhost.h"
#include "pl2303.h"

#define USB_FS_DIR "/dev/bus/usb"
#define USB_FS_ID_SCANNER   "/dev/bus/usb/%d/%d"
#define USB_FS_ID_FORMAT    "/dev/bus/usb/%03d/%03d"

// From drivers/usb/core/devio.c
// I don't know why this isn't in a kernel header
#define MAX_USBFS_BUFFER_SIZE   16384

struct usb_host_context {
    int fd;
};

struct usb_device {
    char dev_name[64];
    unsigned char desc[4096];
    int desc_length;
    int fd;
    int writeable;
};

static inline int badname(const char *name)
{
    while(*name) {
        if(!isdigit(*name++)) return 1;
    }
    return 0;
}

/* returns true if one of the callbacks indicates we are done */
static int find_existing_devices(usb_device_added_cb added_cb,
                                  usb_device_removed_cb removed_cb,
                                  void *client_data)
{
    char busname[32], devname[32];
    DIR *busdir , *devdir ;
    struct dirent *de;
    int done = 0;

    busdir = opendir(USB_FS_DIR);
    if(busdir == 0) return 1;

    while ((de = readdir(busdir)) != 0 && !done) {
        if(badname(de->d_name)) continue;

        snprintf(busname, sizeof busname, "%s/%s", USB_FS_DIR, de->d_name);
        D( "%s/%s\n", USB_FS_DIR, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) continue;

        while ((de = readdir(devdir)) && !done) {
            if(badname(de->d_name)) continue;

            snprintf(devname, sizeof devname, "%s/%s", busname, de->d_name);
            D("    %s/%s\n", busname, de->d_name);
            D(" done = %d, devname = %s\n",done, devname);
            done = 0;
//            added_cb(devname, client_data);
    	    D(" done = %d, devname = %s\n",done, devname);
            } // end of devdir while
        closedir(devdir);
    } //end of busdir while
    closedir(busdir);

    return done;
}

struct usb_host_context *usb_host_init()
{
    struct usb_host_context *context = calloc(1, sizeof(struct usb_host_context));
    if (!context) {
        fprintf(stderr, "out of memory in usb_host_context\n");
        return NULL;
    }
    context->fd = inotify_init();
    if (context->fd < 0) {
        fprintf(stderr, "inotify_init failed\n");
        free(context);
        return NULL;
    }
    return context;
}

void usb_host_cleanup(struct usb_host_context *context)
{
    close(context->fd);
    free(context);
}

void usb_host_run(struct usb_host_context *context,
                  usb_device_added_cb added_cb,
                  usb_device_removed_cb removed_cb,
                  usb_discovery_done_cb discovery_done_cb,
                  void *client_data)
{
    struct inotify_event* event;
    char event_buf[512];
    char path[100];
    int i, ret, done = 0;
    int wd, wds[10];
    int wd_count = sizeof(wds) / sizeof(wds[0]);

    D("Created device discovery thread\n");

    /* watch for files added and deleted within USB_FS_DIR */
    memset(wds, 0, sizeof(wds));
    /* watch the root for new subdirectories */
    wds[0] = inotify_add_watch(context->fd, USB_FS_DIR, IN_CREATE | IN_DELETE);
    if (wds[0] < 0) {
        fprintf(stderr, "inotify_add_watch failed\n");
        if (discovery_done_cb)
        {
    	    D("Discovery done cb\n");
            discovery_done_cb(client_data);
        }
        return;
    }

    /* watch existing subdirectories of USB_FS_DIR */
    for (i = 1; i < wd_count; i++) {
        snprintf(path, sizeof(path), "%s/%03d", USB_FS_DIR, i);
        ret = inotify_add_watch(context->fd, path, IN_CREATE | IN_DELETE);
        if (ret > 0)
            wds[i] = ret;
    }

    /* check for existing devices first, after we have inotify set up */
    done = find_existing_devices(added_cb, removed_cb, client_data);
    	    D("Discovery done=%d\n",done);
    
    if (discovery_done_cb)
        done |= discovery_done_cb(client_data);

    while (!done) {
        ret = read(context->fd, event_buf, sizeof(event_buf));
        if (ret >= (int)sizeof(struct inotify_event)) {
            event = (struct inotify_event *)event_buf;
            wd = event->wd;
            if (wd == wds[0]) {
                i = atoi(event->name);
                snprintf(path, sizeof(path), "%s/%s", USB_FS_DIR, event->name);
                D("new subdirectory %s: index: %d\n", path, i);
                if (i > 0 && i < wd_count) {
                ret = inotify_add_watch(context->fd, path, IN_CREATE | IN_DELETE);
                if (ret > 0)
                    wds[i] = ret;
                }
            } else {
                for (i = 1; i < wd_count && !done; i++) {
                    if (wd == wds[i]) {
                        snprintf(path, sizeof(path), "%s/%03d/%s", USB_FS_DIR, i, event->name);
                        if (event->mask == IN_CREATE) {
                            D("new device %s\n", path);
                            done = added_cb(path, client_data);
                        } else if (event->mask == IN_DELETE) {
                            D("gone device %s\n", path);
                            done = removed_cb(path, client_data);
                        }
                    }
                }
            }
        }
    }
}

struct usb_device *usb_device_open(const char *dev_name)
{
    int fd, did_retry = 0, writeable = 1;

    D("usb_device_open %s\n", dev_name);

retry:
    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        /* if we fail, see if have read-only access */
        fd = open(dev_name, O_RDONLY);
        D("usb_device_open open returned %d errno %d\n", fd, errno);
        if (fd < 0 && (errno == EACCES || errno == ENOENT) && !did_retry) {
            /* work around race condition between inotify and permissions management */
            sleep(1);
            did_retry = 1;
            goto retry;
        }

        if (fd < 0)
            return NULL;
        writeable = 0;
        D("[ usb open read-only %s fd = %d]\n", dev_name, fd);
    }

    struct usb_device* result = usb_device_new(dev_name, fd);
    if (result)
        result->writeable = writeable;
    return result;
}

void usb_device_close(struct usb_device *device)
{
    close(device->fd);
    free(device);
}

struct usb_device *usb_device_new(const char *dev_name, int fd)
{
    struct usb_device *device = calloc(1, sizeof(struct usb_device));
    int length;

    D("usb_device_new %s fd: %d\n", dev_name, fd);

    if (lseek(fd, 0, SEEK_SET) != 0)
        goto failed;
    length = read(fd, device->desc, sizeof(device->desc));
    D("usb_device_new read returned %d errno %d\n", length, errno);
    if (length < 0)
        goto failed;

    strncpy(device->dev_name, dev_name, sizeof(device->dev_name) - 1);
    device->fd = fd;
    device->desc_length = length;
    // assume we are writeable, since usb_device_get_fd will only return writeable fds
    device->writeable = 1;
    return device;

failed:
    D("Error Open new\n");
    close(fd);
    free(device);
    return NULL;
}

static int usb_device_reopen_writeable(struct usb_device *device)
{
    if (device->writeable)
        return 1;

    int fd = open(device->dev_name, O_RDWR);
    if (fd >= 0) {
        close(device->fd);
        device->fd = fd;
        device->writeable = 1;
        return 1;
    }
    D("usb_device_reopen_writeable failed errno %d\n", errno);
    return 0;
}

int usb_device_get_fd(struct usb_device *device)
{
    if (!usb_device_reopen_writeable(device))
        return -1;
    return device->fd;
}

const char* usb_device_get_name(struct usb_device *device)
{
    return device->dev_name;
}

int usb_device_get_unique_id(struct usb_device *device)
{
    int bus = 0, dev = 0;
    sscanf(device->dev_name, USB_FS_ID_SCANNER, &bus, &dev);
    return bus * 1000 + dev;
}

int usb_device_get_unique_id_from_name(const char* name)
{
    int bus = 0, dev = 0;
    sscanf(name, USB_FS_ID_SCANNER, &bus, &dev);
    return bus * 1000 + dev;
}

char* usb_device_get_name_from_unique_id(int id)
{
    int bus = id / 1000;
    int dev = id % 1000;
    char* result = (char *)calloc(1, strlen(USB_FS_ID_FORMAT));
    snprintf(result, strlen(USB_FS_ID_FORMAT) - 1, USB_FS_ID_FORMAT, bus, dev);
    return result;
}

uint16_t usb_device_get_vendor_id(struct usb_device *device)
{
    struct usb_device_descriptor* desc = (struct usb_device_descriptor*)device->desc;
    return __le16_to_cpu(desc->idVendor);
}

uint16_t usb_device_get_product_id(struct usb_device *device)
{
    struct usb_device_descriptor* desc = (struct usb_device_descriptor*)device->desc;
    return __le16_to_cpu(desc->idProduct);
}

const struct usb_device_descriptor* usb_device_get_device_descriptor(struct usb_device *device)
{
    return (struct usb_device_descriptor*)device->desc;
}

char* usb_device_get_string(struct usb_device *device, int id)
{
    char string[256];
    __u16 buffer[128];
    __u16 languages[128];
    int i, result;
    int languageCount = 0;

    string[0] = 0;
    memset(languages, 0, sizeof(languages));

    // read list of supported languages
    result = usb_device_control_transfer(device,
            USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE, USB_REQ_GET_DESCRIPTOR,
            (USB_DT_STRING << 8) | 0, 0, languages, sizeof(languages), 0);
    if (result > 0)
        languageCount = (result - 2) / 2;

    for (i = 1; i <= languageCount; i++) {
        memset(buffer, 0, sizeof(buffer));

        result = usb_device_control_transfer(device,
                USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE, USB_REQ_GET_DESCRIPTOR,
                (USB_DT_STRING << 8) | id, languages[i], buffer, sizeof(buffer), 0);
        if (result > 0) {
            int i;
            // skip first word, and copy the rest to the string, changing shorts to bytes.
            result /= 2;
            for (i = 1; i < result; i++)
                string[i - 1] = buffer[i];
            string[i - 1] = 0;
            return strdup(string);
        }
    }

    return NULL;
}

char* usb_device_get_manufacturer_name(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iManufacturer)
        return usb_device_get_string(device, desc->iManufacturer);
    else
        return NULL;
}

char* usb_device_get_product_name(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iProduct)
        return usb_device_get_string(device, desc->iProduct);
    else
        return NULL;
}

char* usb_device_get_serial(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iSerialNumber)
        return usb_device_get_string(device, desc->iSerialNumber);
    else
        return NULL;
}

int usb_device_is_writeable(struct usb_device *device)
{
    return device->writeable;
}

void usb_descriptor_iter_init(struct usb_device *device, struct usb_descriptor_iter *iter)
{
    iter->config = device->desc;
    iter->config_end = device->desc + device->desc_length;
    iter->curr_desc = device->desc;
}

struct usb_descriptor_header *usb_descriptor_iter_next(struct usb_descriptor_iter *iter)
{
    struct usb_descriptor_header* next;
    if (iter->curr_desc >= iter->config_end)
        return NULL;
    next = (struct usb_descriptor_header*)iter->curr_desc;
    iter->curr_desc += next->bLength;
    return next;
}

int usb_device_claim_interface(struct usb_device *device, unsigned int interface)
{
    return ioctl(device->fd, USBDEVFS_CLAIMINTERFACE, &interface);
}

int usb_device_release_interface(struct usb_device *device, unsigned int interface)
{
    return ioctl(device->fd, USBDEVFS_RELEASEINTERFACE, &interface);
}

int usb_device_connect_kernel_driver(struct usb_device *device,
        unsigned int interface, int connect)
{
    struct usbdevfs_ioctl ctl;

    ctl.ifno = interface;
    ctl.ioctl_code = (connect ? USBDEVFS_CONNECT : USBDEVFS_DISCONNECT);
    ctl.data = NULL;
    return ioctl(device->fd, USBDEVFS_IOCTL, &ctl);
}

int usb_device_control_transfer(struct usb_device *device,
                            int requestType,
                            int request,
                            int value,
                            int index,
                            void* buffer,
                            int length,
                            unsigned int timeout)
{
    struct usbdevfs_ctrltransfer  ctrl;

    // this usually requires read/write permission
    if (!usb_device_reopen_writeable(device))
        return -1;

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.bRequestType = requestType;
    ctrl.bRequest = request;
    ctrl.wValue = value;
    ctrl.wIndex = index;
    ctrl.wLength = length;
    ctrl.data = buffer;
    ctrl.timeout = timeout;
    return ioctl(device->fd, USBDEVFS_CONTROL, &ctrl);
}

int usb_device_bulk_transfer(struct usb_device *device,
                            int endpoint,
                            void* buffer,
                            int length,
                            unsigned int timeout)
{
    struct usbdevfs_bulktransfer  ctrl;

    // need to limit request size to avoid EINVAL
    if (length > MAX_USBFS_BUFFER_SIZE)
        length = MAX_USBFS_BUFFER_SIZE;

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.ep = endpoint;
    ctrl.len = length;
    ctrl.data = buffer;
    ctrl.timeout = timeout;
    return ioctl(device->fd, USBDEVFS_BULK, &ctrl);
}

struct usb_request *usb_request_new(struct usb_device *dev,
        const struct usb_endpoint_descriptor *ep_desc)
{
    struct usbdevfs_urb *urb = calloc(1, sizeof(struct usbdevfs_urb));
    if (!urb)
        return NULL;

    if ((ep_desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK)
        urb->type = USBDEVFS_URB_TYPE_BULK;
    else if ((ep_desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_INT)
        urb->type = USBDEVFS_URB_TYPE_INTERRUPT;
    else {
        D("Unsupported endpoint type %d", ep_desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK);
        free(urb);
        return NULL;
    }
    urb->endpoint = ep_desc->bEndpointAddress;

    struct usb_request *req = calloc(1, sizeof(struct usb_request));
    if (!req) {
        free(urb);
        return NULL;
    }

    req->dev = dev;
    req->max_packet_size = __le16_to_cpu(ep_desc->wMaxPacketSize);
    req->private_data = urb;
    req->endpoint = urb->endpoint;
    urb->usercontext = req;

    return req;
}

void usb_request_free(struct usb_request *req)
{
    free(req->private_data);
    free(req);
}

int usb_request_queue(struct usb_request *req)
{
    struct usbdevfs_urb *urb = (struct usbdevfs_urb*)req->private_data;
    int res;

    urb->status = -1;
    urb->buffer = req->buffer;
    // need to limit request size to avoid EINVAL
    if (req->buffer_length > MAX_USBFS_BUFFER_SIZE)
        urb->buffer_length = MAX_USBFS_BUFFER_SIZE;
    else
        urb->buffer_length = req->buffer_length;

    do {
        res = ioctl(req->dev->fd, USBDEVFS_SUBMITURB, urb);
    } while((res < 0) && (errno == EINTR));

    return res;
}

struct usb_request *usb_request_wait(struct usb_device *dev)
{
    struct usbdevfs_urb *urb = NULL;
    struct usb_request *req = NULL;
    int res;

    while (1) {
        int res = ioctl(dev->fd, USBDEVFS_REAPURB, &urb);
        D("USBDEVFS_REAPURB returned %d\n", res);
        if (res < 0) {
            if(errno == EINTR) {
                continue;
            }
            D("[ reap urb - error ]\n");
            return NULL;
        } else {
            D("[ urb @%p status = %d, actual = %d ]\n",
                urb, urb->status, urb->actual_length);
            req = (struct usb_request*)urb->usercontext;
            req->actual_length = urb->actual_length;
        }
        break;
    }
    return req;
}

int usb_request_cancel(struct usb_request *req)
{
    struct usbdevfs_urb *urb = ((struct usbdevfs_urb*)req->private_data);
    return ioctl(req->dev->fd, USBDEVFS_DISCARDURB, &urb);
}






//my function
//Find device from table


//sizeof id_table = 200????
//на самом деле 49

struct usb_device* find_device()
{
    struct usb_device* device=NULL; 

    int i;
	for(i=0; i < 49;i++)
	{
    	    printf("Searching for device VID_%04x&PID_%04x\n",id_table[i].VID, id_table[i].PID);
//    	    usleep(100000);
	    device = find_device_by_VID_PID(id_table[i].VID, id_table[i].PID);


	    if(device != NULL)
    	    {
    		printf("Found PL2303 device VID_%04x&PID%04x (Index=%d)\n",id_table[i].VID, id_table[i].PID,i);
    		return device;
	    }
	}
	return NULL;
}
    int count=0;

struct usb_device* find_device_by_VID_PID(unsigned short VID, unsigned short PID)
{
    char busname[32], devname[32];
    DIR *busdir , *devdir ;
    struct dirent *de;
    int done = 0;
    struct usb_device *device; 
    unsigned short mVID,mPID;
    
    busdir = opendir(USB_FS_DIR);
    if(busdir == 0) return NULL;

    while ((de = readdir(busdir)) != 0 && !done) 
    {
        if(badname(de->d_name)) continue;

        snprintf(busname, sizeof busname, "%s/%s", USB_FS_DIR, de->d_name);
//        D( "%s/%s\n", USB_FS_DIR, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) 
    	    continue;

        while ((de = readdir(devdir)) && !done) 
        {
            if(badname(de->d_name)) 
        	continue;
            snprintf(devname, sizeof devname, "%s/%s", busname, de->d_name);
            //here call function for fill device
//	    printf("COUNT = %d\n",count++);
	    
	    device = usb_device_open(devname);
	    mVID = usb_device_get_vendor_id(device);
	    mPID = usb_device_get_product_id(device);
	    if(mVID == VID && mPID == PID)
	    {
		done = 1;
	    } 
	    	    
        } // end of devdir while
        closedir(devdir);
    } //end of busdir while
    closedir(busdir);

    if(done == 1)
	return device;
    else 
	return NULL;;
}


static int pl2303_vendor_read(__u16 value, __u16 index, 
		struct usb_device *dev, unsigned char *buf)
{
	int res = usb_device_control_transfer(dev, VENDOR_READ_REQUEST_TYPE, VENDOR_READ_REQUEST,
			value, index, buf, 1, 100);
	D("0x%x:0x%x:0x%x:0x%x  %d - %x", VENDOR_READ_REQUEST_TYPE,
			VENDOR_READ_REQUEST, value, index, res, buf[0]);
	return res;
}

static int pl2303_vendor_write(__u16 value, __u16 index,
		struct usb_device *dev)
{
	int res = usb_device_control_transfer(dev, 	VENDOR_WRITE_REQUEST_TYPE, VENDOR_WRITE_REQUEST,
			value, index, NULL, 0, 100);
	D("0x%x:0x%x:0x%x:0x%x  %d", VENDOR_WRITE_REQUEST_TYPE,
			VENDOR_WRITE_REQUEST, value, index, res);
	return res;
}

int pl2303_startup(struct usb_device *dev)
{

	struct usb_device_descriptor *descriptor = (struct usb_device_descriptor *)dev->desc;

	struct pl2303_private *priv;
	enum pl2303_type type = type_0;
	unsigned char *buf;
	int i;
	unsigned int interface=0;

	//disconnect kernel and claim interface 
	usb_device_connect_kernel_driver(dev, interface, 0);
	usb_device_claim_interface(dev,  interface);


	buf = malloc(10);
	if (buf == NULL)
		return -ENOMEM;

	if (descriptor->bDeviceClass == 0x02)
		type = type_0;
	else if (descriptor->bMaxPacketSize0 == 0x40)
		type = HX;
	else if (descriptor->bDeviceClass == 0x00)
		type = type_1;
	else if (descriptor->bDeviceClass == 0xFF)
		type = type_1;
	D("device type: %d", type);

//	for (i = 0; i < serial->num_ports; ++i) {
//		priv = kzalloc(sizeof(struct pl2303_private), GFP_KERNEL);
//		if (!priv)
//			goto cleanup;
//		spin_lock_init(&priv->lock);
//		init_waitqueue_head(&priv->delta_msr_wait);
//		priv->type = type;
//		usb_set_serial_port_data(serial->port[i], priv);
//	}

	pl2303_vendor_read(0x8484, 0, dev, buf);
	pl2303_vendor_write(0x0404, 0, dev);
	pl2303_vendor_read(0x8484, 0, dev, buf);
	pl2303_vendor_read(0x8383, 0, dev, buf);
	pl2303_vendor_read(0x8484, 0, dev, buf);
	pl2303_vendor_write(0x0404, 1, dev);
	pl2303_vendor_read(0x8484, 0, dev, buf);
	pl2303_vendor_read(0x8383, 0, dev, buf);
	pl2303_vendor_write(0, 1, dev);
	pl2303_vendor_write(1, 0, dev);
	if (type == HX)
		pl2303_vendor_write(2, 0x44, dev);
	else
		pl2303_vendor_write(2, 0x24, dev);

	free(buf);
	return 0;

}


//URB HEAD
    __u64  URB_ID;
    __u8  URB_TYPE;
    __u8  URB_TRANSFER_TYPE;
    __u8  Endpoint;
    __u8  Device;
    __u8  Bus;
    __u8  DeviceRequest;
    __u8  DataPresent;
    __u64  TimeSec;
    __u32 TimeMsec;
    __u32 URB_STATUS;
    __u32 URB_LEN;
    __u32 DATA_LEN;


//URB_SETUP
    __u8  RequestType;
    __u8  Request;
    __u16 Value;
    __u16 Index;
    __u16 Len;
    __u8  buff[16];


int pl2303_open(struct usb_device* device, int baudrate)
{

    char buffer[256];
    int ret;
//URB CONTROL
	RequestType = 0x40;
	Request = 0x1;
	Value = 0x8;
	Index = 0x0;
	Len = 0;
	
	 printf("CTL=%d : ", usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x40;
	Request = 0x1;
	Value = 0x9;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d : ",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0xa1;
	Request = 0x21;
	Value = 0x0;
	Index = 0x0;
	Len = 7;
	 printf("CTL=%d : ",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x21;
	Request = 0x20;
	Value = 0x0;
	Index = 0x0;
	Len = 7;

//	buffer[0] = 0xC0; // 0x80; // baudrate
//	buffer[1] = 0x12; // 0x25;

	buffer[0] = ((unsigned char *)(&baudrate))[0];
	buffer[1] = ((unsigned char *)(&baudrate))[1];

	buffer[2] = 0x0;
	buffer[3] = 0x0;
	buffer[4] = 0x0;
	buffer[5] = 0x0;
	buffer[6] = 0x8;
	 printf("CTL=%d : ",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x21;
	Request = 0x22;
	Value = 0x3;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0xa1;
	Request = 0x21;
	Value = 0x0;
	Index = 0x0;
	Len = 7;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x40;
	Request = 0x1;
	Value = 0x0;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));
//URB BULK
	Endpoint = 0x83;
	Len = 256;
	 printf("BLK=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("RD=0x%x : ",*buffer);
//URB INTERR
	Endpoint = 0x81;
	Len = 10;
	 printf("INT=%d :",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("RD=0x%x :",*buffer);
//URB CONTROL
	RequestType = 0x21;
	Request = 0x22;
	Value = 0x3;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));
//URB INTERR
	Endpoint = 0x81;
	Len = 256;
	 printf("INT=%d :",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("RD=0x%x :",*buffer);
        
        return 0;
        
//URB bulk
    for(;;)
    {
	Endpoint = 0x83;
	Len = 256;
	memset(buffer,0,sizeof(buffer));
	pl2303_read(device,buffer,Len);
//	ret= usb_device_bulk_transfer(device, Endpoint, buffer, Len, 400);
        //if(ret>0)
    	//    printf("%s",buffer);
//        printf("RET(;)=%d\n",
//        printf("Read %s\n",buffer);
	usleep(150000);
    }
//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB INTERR
	Endpoint = 0x81;
	Len = 10;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);

//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);

//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("RET( bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB INTERR
	Endpoint = 0x81;
	Len = 1;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);

//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("RET( bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("RET( bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB INTERR
	Endpoint = 0x81;
	Len = 1;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//URB bulk
	Endpoint = 0x83;
	Len = 256;
	 printf("INT=%d : ",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);

// 48- paket
return 0;


//URB CONTROL
	RequestType = 0x40;
	Request = 0x1;
	Value = 0x0;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

	Endpoint = 0x83;
	Len = 0;
//	buffer[0] = 0x2c;
//	buffer[1] = 0x30;
//	buffer[2] = 0x66;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("Read %s\n",buffer);
//    usleep(100000);

return 0;


//URB CONTROL
//	RequestType = 0x21;
//	Request = 0x20;
//	Value = 0x0;
//	Index = 0x0;
//	Len = 7;
//	buffer[0] = 0x80;
//	buffer[1] = 0x25;
//	buffer[2] = 0x0;
//	buffer[3] = 0x0;
//	buffer[4] = 0x0;
//	buffer[5] = 0x0;
//	buffer[6] = 0x8;
//	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x21;
	Request = 0x22;
	Value = 0x3;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
//	RequestType = 0xa1;
//	Request = 0x21;
//	Value = 0x0;
//	Index = 0x0;
//	Len = 0;
//	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x40;
	Request = 0x1;
	Value = 0x0;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d :",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB BULK
//	Endpoint = 0x83;
//	Len = 0;
//	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB INTERRUPT
//	Endpoint = 0x81;
//	Len = 0;
//	 printf("RET(interr)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB CONTROL
	RequestType = 0x21;
	Request = 0x22;
	Value = 0x3;
	Index = 0x0;
	Len = 0;
	 printf("CTL=%d : ",usb_device_control_transfer(device, RequestType, Request, Value, Index, buffer, Len, 100));

//URB BULK
//for(;;)
//{
//    usleep(100000);
//URB INTERRUPT
//	Endpoint = 0x81;
//	Len = 1;
//	printf("RET(interr)=%d\n",	 usb_device_bulk_transfer(device, Endpoint, buffer, Len, 500));
//        printf("%s\n",buffer);
    usleep(100000);
	Endpoint = 0x83;
	Len = 1;
//	buffer[0] = 0x2c;
//	buffer[1] = 0x30;
//	buffer[2] = 0x66;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 500));
        printf("Read %s\n",buffer);
    usleep(100000);
	Endpoint = 0x81;
	Len = 1;
//	buffer[0] = 0x2c;
//	buffer[1] = 0x30;
//	buffer[2] = 0x66;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 500));
        printf("Read %s\n",buffer);
//    usleep(100000);
	Endpoint = 0x83;
	Len = 1;
//	buffer[0] = 0x2c;
//	buffer[1] = 0x30;
//	buffer[2] = 0x66;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 500));
        printf("Read %s\n",buffer);
	Endpoint = 0x83;
	Len = 1;
//	buffer[0] = 0x2c;
//	buffer[1] = 0x30;
//	buffer[2] = 0x66;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 500));
        printf("Read %s\n",buffer);
//}
return 0;
//URB BULK
	Endpoint = 0x83;
	Len = 1;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("%s\n",buffer);
return 0;
//URB INTERRUPT
	Endpoint = 0x81;
	Len = 1;
	printf("RET(interr)=%d\n",	 usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("%s\n",buffer);


//URB BULK
	Endpoint = 0x83;
	Len = 1;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("%s\n",buffer);
/*
//URB INTERRUPT
	Endpoint = 0x81;
	Len = 10;
 printf("RET(interr)=%d\n",	 usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
        printf("%s\n",buffer);

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 0;
	 usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100);

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0x19;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 2;
	buffer[0] = 0x6;
	buffer[1] = 0x6;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 10;
	 printf("RET(interr)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 0;
	 printf("RET(interr)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0xc6;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0xa6;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	 printf("RET(bulk;)=%d\n",usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 10;
	 printf("RET(interr)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 0;
	 printf("RET(interr)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0x76;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0x86;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0xd6;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
//URB INTERRUPT
	Endpoint = 0x81;
	Len = 10;
	 usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100);

//URB INTERRUPT
	Endpoint = 0x81;
	Len = 0;
	 printf("RET(interr)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 1;
	buffer[0] = 0xa;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));

//URB BULK
	Endpoint = 0x83;
	Len = 0;
	printf("RET(bulk;)=%d\n", usb_device_bulk_transfer(device, Endpoint, buffer, Len, 100));
*/
}



int pl2303_read( struct usb_device *device, char *buff, int len)
{    
    int i;
    static    char b[10];
//    return 0;
//    for(i=0; i < len; i++)
//    {
	Endpoint = 0x83;
	Len = len;
	i=usb_device_bulk_transfer(device, 0x83, buff, Len, 400);
//	printf("%s",buff);
//	printf("b=%s %d (errno)\n",b,i);
//	perror("read");
//    }
    return i;
}

int pl2303_write( struct usb_device *device, char *buff, int len)
{    
    int i;
    static    char b[10];
//    return 0;
//    for(i=0; i < len; i++)
//    {
	Endpoint = 0x03;
	Len = len;
	i=usb_device_bulk_transfer(device, Endpoint, buff, Len, 400);
//	printf("%s",buff);
//	printf("b=%s %d (errno)\n",b,i);
//	perror("read");
//    }
    return i;
}

/*
int usb_device_bulk_transfer(struct usb_device *device,
                            USB_DIR,
                            void* buffer,
                            int length,
                            unsigned int timeout)


static int set_control_lines(struct usb_device *dev, u8 value)
{
	int retval;

	retval = usb_control_transfer(dev, SET_CONTROL_REQUEST, SET_CONTROL_REQUEST_TYPE,
				 value, 0, NULL, 0, 100);
	D("%s - value = %d, retval = %d", __func__, value, retval);
	return retval;
}

*/




