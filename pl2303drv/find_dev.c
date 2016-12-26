#include <stdio.h>
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
#include <termios.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>



#include "usbhost.h"

int check_run()
{

    FILE *fp;
    int val;
	fp = fopen("pl2303_oper","r");
	if(fp == 0) //если файла нет выходим
	    return(-1);
	fscanf(fp,"%d",&val);
	// printf("Check run :: %d\n",val);
	if(val == 0)
	    return -1;
	fclose(fp);
	return 0;
}

D(char *s)
{
    char buff[256];
    sprintf(buff,"echo %s > pl2303_err", s);
    system(buff);
}


int sPORT=22334;


int main(int argc,char **argv)
{

    struct usb_host_context *uhc;
    struct usb_device* device=NULL;
    char *dev_name;
    usb_device_added_cb added_cb;
    usb_device_removed_cb removed_cb;
    usb_discovery_done_cb discovery_done_cb;
    void *ud;
    char buff[256];
    
    int len_log = 0;
    int len = 256;
    int res;
    int i;
    int val_oper;
    int err_num=0;
    int baudrate=0;

    int fd;
    struct termios settings;

    FILE *fp_log; //сюда будем писать ошибки
    FILE *fp_oper;//файл для управления 1 пускаемся и ищем девайс 0-выходим из программы

    unsigned short PID=0x2303,VID=0x067b;

    char tty_name[128];

    unsigned int length;
    struct sockaddr_in server;
    char buf[128];
    int rval, ret;
    float temp;
    int sock;
    
    struct hostent *hp;
    
    printf("\nPL2303drv by vovan.v.rum, mod by Ao'Gf\n--------------------------------------\n\n");

 if (argc < 3) {
	printf("Usage: pl2303drv device baudrate. Example: pl2303drv /dev/ttyUSB0 4800\n");
	return 0;
	}


        strncpy(tty_name,argv[1],128);

        device = (void*)find_device();
        if(device == NULL)
        {
		printf("Device from table not found\n");
		D("-1");
		return 0;
        }

    sscanf(argv[2],"%d",&baudrate);
    printf("Baudrate requested: %d\n",baudrate);

    
    D("1110");
    device = find_device_by_VID_PID(VID, PID);

    if(device == NULL)
    {
	    printf("Device not found\n");
	    D("-1");
	    return 0;
    }


    D("0");

    //открываем псевдо tty

    printf("Creating virtual tty. ");

    fd = open("/dev/ptmx", O_RDWR|O_NONBLOCK|O_NOCTTY);
    grantpt(fd);
    unlockpt(fd);
    
    tcgetattr(fd,&settings);
    settings.c_lflag |=ICANON;
    settings.c_lflag &=~ECHO;
    settings.c_lflag &=~ECHONL;
    
    tcsetattr(fd, TCSANOW, &settings);

//    fp_log = fopen("pl2303_log.txt","w"); // start system log
//    chmod("pl2303_log.txt",0666);
    
    printf("Virtual port: %s\n",ptsname(fd));   // show file descriptor

    unlink(tty_name);
    printf("System: unlink %s\n",tty_name);

    symlink((void*)ptsname(fd),tty_name);
    printf("System: symlink(%s,%s)\n",ptsname(fd),tty_name);

    printf("PL2303 serial installed on %s. Type `cat %s` in another shell window to test.\n\n",tty_name,tty_name);

    printf("System: chmod 0666 %s\n",ptsname(fd));
    printf("System: chmod 0666 %s\n",tty_name);
    chmod(ptsname(fd),0666);
    chmod(tty_name,0666);

    pl2303_startup(device);
    pl2303_open(device,baudrate);

    printf("\n\n");

    for(;;)
    {
	if (err_num) printf("err_num - %d\n",err_num);

//	//проверяем надо ли уходить
//	if(check_run() <0 ) {
//	printf("pl2303_oper not found.");
//	    return 0;
//	}
	
        memset(buff,0,sizeof(buff));
        res=pl2303_read(device,buff,sizeof(buff));
        if(res>0)
        {
    		// fwrite(buff,res,1,fp_log);
    		// fflush(fp_log);
		write(fd,buff,res);;
    		len_log = len_log+res;        
		// printf("Bytes read: %d            \r",len_log);

            //если лог будет превышать 65кбайт переписываем
	    //    if(len_log >= 65536)
    	//	{
    	//	    fclose(fp_log);
    	//	    len_log = 0;
	//	    fp_log = fopen("pl2303_log.txt","w");
	//	    fprintf(fp_log,"-----------New log--------- \n");
	    
    	//	}
    		err_num = 0;
	}
        else  //if(res < 0 )
        {
    	    err_num++;
    	    if(err_num == 4)
    	    {
    	      //отключили девайс
            	D("-2");
    		return 0;
            }
    	}
	
        memset(buff,0,sizeof(buff));
	if(read(fd,buff,res)>0)
	{
//	    printf("Write to pl2303:%s\n",buff);
	    pl2303_write(device,buff,sizeof(buff));
	}
	usleep(150000);
    }
}
