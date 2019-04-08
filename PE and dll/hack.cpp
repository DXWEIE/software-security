#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
//节表 
struct section_header{
	uint8_t name[8];//DLL名字
	uint8_t virtualsize[4];
	uint8_t RVA[4];//内存中地址
	uint8_t size_of_raw_data[4];//节大小
	uint8_t file_address[4];//文件中地址,RVA-file_addr得到本节中delta
	uint8_t notimportant[16]; 
};

//IDT项
struct IDT_entry{
	uint32_t INT_pointer;//指向INT表
	uint32_t timestamp;
	uint32_t forwarderchain;
	uint32_t dll_name_pointer;//指向DLL名字
	uint32_t IAT_pointer;//指向IAT表
};

//获取文件字节数 
int file_size(char* filename)
{
    struct stat statbuf;
    stat(filename,&statbuf);
    int size=statbuf.st_size;
    return size;
}

uint32_t uint8to32(uint8_t fouruint8[4]) {
	return *(uint32_t*)fouruint8;	
}

uint16_t uint8to16(uint8_t fouruint8[2]) {
	return *(uint16_t*)fouruint8;	
}

uint32_t findgap(uint8_t*exebuffer,uint32_t old_import_table_addr,uint32_t old_import_table_size,uint32_t gapsize,uint32_t buffersize)
{
	uint8_t orresult=0;//相或为0，则有长串0
	for(uint32_t i=old_import_table_addr+old_import_table_size;i<old_import_table_addr+old_import_table_size+gapsize-20;i++){
			orresult=exebuffer[old_import_table_addr+old_import_table_size]|orresult;
	} 
	if(orresult==0)//可以不用搬家,否则还需要继续找 
		return  old_import_table_addr;
	
	//需要搬家 
	int flag=0;
	orresult=0;
	uint32_t index=old_import_table_addr+old_import_table_size+gapsize-20;
	uint32_t gap_begin_addr=0;
	while(flag==0&&index<buffersize)
	{
		for(int i=0;i<gapsize;i++){
			if(exebuffer[index+i]!=0x00){
				orresult=1;
				index=index+i+1;
				break;
			}
		}
		if(orresult==0)//找到了gap 
		{
			//printf("!find gap!\n");
			flag=1;
			gap_begin_addr=index;
			break;
		}
		orresult=0;
	}
	return gap_begin_addr;
}

uint32_t finddatagap(uint8_t*exebuffer,uint32_t old_import_table_addr,uint32_t old_import_table_size,uint32_t gapsize,uint32_t buffersize)
{
	uint8_t orresult=0;//相或为0，则有长串0

	int flag=0;
	orresult=0;
	uint32_t index=old_import_table_addr;
	uint32_t gap_begin_addr=0;
	while(flag==0&&index<buffersize)
	{
		for(int i=0;i<gapsize;i++){
			if(exebuffer[index+i]!=0x00){
				orresult=1;
				index=index+i+1;
				break;
			}
		}
		if(orresult==0)//找到了gap 
		{
			//printf("!find gap!\n");
			flag=1;
			gap_begin_addr=index;
			break;
		}
		orresult=0;
	}
	return gap_begin_addr;
}


int main(int argc,char**argv){
	FILE *fp=NULL;
	int filesize=0;//文件总字节数 
	if(argc!=2){
		printf("use like this:  hack.exe target.exe!\n");
		return 0;
	}
	
	fp=fopen(argv[1],"rb+");
	if(fp==NULL){
		printf("open file %s failed!\n",argv[1]);
		return 0;
	}
	filesize=file_size(argv[1]);//文件总大小
	uint8_t  *exebuffer=(uint8_t*)malloc(filesize);//要写回，大小不要随意改变
	
	int readsize=fread(exebuffer,1,filesize,fp);
	if(readsize==0){
		printf("read %s failed!\n",argv[1]);
		return 0;
	}
	else{
		printf("filesize is %d, readsize is %d\n",filesize,readsize);
	} 
	//检查是不是PE文件 
	uint16_t pehead=uint8to16(exebuffer);
	if(pehead!=0x5a4d){
		printf("PE head is %0X,not a PE file!\n",pehead);
		return 0;
	}
	
	uint32_t NT_header_index=uint8to32(&exebuffer[60]);//0x3C
	//printf("NT header is at %0X\n",NT_header_index);
	uint32_t signature=uint8to32(&exebuffer[NT_header_index]);
	//"PE" 50 45
	if(signature!=0x4550){
		printf("PE head is %0X,not a PE file!\n",signature);
		return 0;
	}
	
	uint16_t sections=uint8to16(&exebuffer[NT_header_index+4+2]);//有多少个节,可能需要读多少个节表 
	//0x4+0x14=20字节，可选头从NT_header_index+24开始
	uint16_t option_header_size=uint8to16(&exebuffer[NT_header_index+4+16]);//可选头大小 
	
	uint32_t option_header_index=NT_header_index+24;//可选头开始 
	uint32_t num_of_directory=uint8to32(&exebuffer[option_header_index+92]);//0x5C,一般是0x10
	//每项8字节，引入表在第2项,目录第1项在偏移option_header_index的0x60=96 
	uint32_t* import_table_addr=(uint32_t*)&exebuffer[option_header_index+96+8];//之后可能要搬家 
	uint32_t* import_table_size=(uint32_t*)&exebuffer[option_header_index+96+12];//直接使用指针，之后要加20 
	 
	uint32_t* bound_table_addr=(uint32_t*)&exebuffer[option_header_index+96+88];//如果绑定表有的话，清空 
	uint32_t* bound_table_size=(uint32_t*)&exebuffer[option_header_index+96+92];//清0	
	//printf("引入表在%0X,大小为%0X\n",*import_table_addr,*import_table_size);
	//printf("绑定表在%0X,大小为%0X\n",*bound_table_addr,*bound_table_size);
	//如果有绑定表，清0 
	if(*bound_table_size!=0){
		*bound_table_addr=0;
		*bound_table_size=0;
	}
	
	uint32_t *section_delta_offset=(uint32_t*)malloc(sections*sizeof(uint32_t));
	struct section_header *the_section_header=
	     (struct section_header *)malloc(sections*sizeof(struct section_header));
	memset(the_section_header,0,sections*40);
	memcpy(the_section_header,&exebuffer[option_header_index+option_header_size],sections*40);
	//通过pointer to raw data判断现在在哪个节里面，需要使用哪个节的delta 
	//file_offset+delta=RVA，PE文件中记录的是RVA 
	//同时记录.data节的序号 
	int datasectionnum=-1;
	for(int i=0;i<sections;i++){
		section_delta_offset[i]=uint8to32(the_section_header[i].RVA) - 
		                        uint8to32(the_section_header[i].file_address);
		if(!strcmp((char*)the_section_header[i].name,".data")||!strcmp((char*)the_section_header[i].name,"data"))
			datasectionnum=i;
	}
	printf("data section  is in the %d place. \n",datasectionnum);
	//寻找空隙 20字节IDT新项，4字节指针[INT]，20字节函数序号和名，4字节前面指针的INT结尾 
	//16字节的Func.dll名字，IAT表指针，和IAT表0000000 
	uint32_t  gapsize=*import_table_size+20+4+20+4+16+8+3;//至少需要那么大的空隙,四字节对齐 
	//往后找空隙，返回开始的文件偏移号；如果往后找不到，可能直下一步接往.data中找 
	//需要先把引入表的RVA转为文件偏移
	uint32_t import_table_fileaddr=0;
	for(int i=0;i<sections;i++){
		if(i!=sections-1)
		{
			if(*import_table_addr>=uint8to32(the_section_header[i].RVA) && *import_table_addr<uint8to32(the_section_header[i+1].RVA))
			{
				import_table_fileaddr=*import_table_addr-section_delta_offset[i];
				break;
			}
		}
		else if(i==sections-1){
			import_table_fileaddr=*import_table_addr-section_delta_offset[i];
			break;
		}

	} 
	uint32_t gap_firstindex=findgap(exebuffer,import_table_fileaddr,*import_table_size,gapsize,filesize);
	//如果找到了这么大的空隙 
	if(gap_firstindex!=0){
		gap_firstindex=gap_firstindex+4-(gap_firstindex%4);
		printf("Find enough gap! It starts at file-offset %0X\n",gap_firstindex);
	}
	else//尝试在数据区找到空隙 
	{
		gap_firstindex=finddatagap(exebuffer,uint8to32(the_section_header[datasectionnum].file_address),*import_table_size,gapsize,filesize);
		if(gap_firstindex!=0){
			gap_firstindex=gap_firstindex+4-(gap_firstindex%4);
			printf("Find enough gap! It starts at file-offset %0X\n",gap_firstindex);
		}
		else{
			printf("Operation failed! No enough gap to change!\n");
			return 0;
		}
	}	
	
	//定位gap所在节,决定offset和节名 
	uint32_t gap_firstRVA=0;
	for(int i=0;i<sections;i++){
		if(i!=sections-1)
		{
			if(gap_firstindex>=uint8to32(the_section_header[i].file_address) && gap_firstindex<uint8to32(the_section_header[i+1].file_address))
			{
				gap_firstRVA=gap_firstindex+section_delta_offset[i];
				break;
			}
		}
		else if(i==sections-1){
			gap_firstRVA=gap_firstindex+section_delta_offset[i];
			break;
		}
	} 
	printf("\nFirstRVA of the gap area is %0X, the new import table will at here.\n",gap_firstRVA);
	
	//有了开始的文件偏移和RVA，可以开始了！先把原来的表复制过去 
	uint32_t rel_current_RVA=0;//修改时的相对偏移
	uint32_t rel_current_index=0;//修改时的相对偏移
	//printf("sizeof section header is %d\n",*import_table_size);
	//不用把全零的结尾复制进去 
	//注意放的是RVA!!!! 
	memcpy(&exebuffer[gap_firstindex],&exebuffer[import_table_fileaddr],*import_table_size-20); 
	rel_current_index=gap_firstindex+*import_table_size-20;//此时的新IDT项放的文件地址 
	rel_current_RVA=gap_firstRVA+*import_table_size-20;//此时的新IDT项放的RVA地址
	//printf("rel_current_RVA is %X\n",rel_current_RVA);
	*import_table_addr=gap_firstRVA;//切换引入表 
	*import_table_size=*import_table_size+20;//增加引入表项
	struct IDT_entry new_IDT_entry;
	new_IDT_entry.INT_pointer=rel_current_RVA+40;//1个IDT项，1个空的，20+20,自己占用4+4[1个空指针]
	// rel_current_index+40这里放1个INT项，1个零，共8字节 
	*(uint32_t*)&exebuffer[rel_current_index+40]=(uint32_t)rel_current_RVA+48;
	exebuffer[rel_current_index+48]=0x01;//0001，这里是Func.dll的里面的到处函数FuncInDll项的开始 
	//50开始是函数名,虽然并没有在EXE中执行LoadLibrary和GetProcAddress，加载DLL直接进DllMain 
	strcpy((char*)&exebuffer[rel_current_index+50],"FuncInDll"); 
	 
	new_IDT_entry.timestamp=0x0;
	new_IDT_entry.forwarderchain=0x0;
	new_IDT_entry.dll_name_pointer=(uint32_t)rel_current_RVA+50+20;//之前分配的20字节 
	strcpy((char*)&exebuffer[rel_current_index+50+20],"Func.dll");//DLL的名字 
	//一个指向IAT表指针的指针，告诉IAT指针在哪 
	new_IDT_entry.IAT_pointer=rel_current_RVA+50+20+14;
	printf("IAT_pointer at %X\n",new_IDT_entry.IAT_pointer);
	uint32_t IAT_RVA=rel_current_RVA+48;//Func.dll的IAT的RVA 
	memcpy(&exebuffer[rel_current_index+50+20+14],&IAT_RVA,4);
	IAT_RVA=0x0;//填0，应该后面是4字节0作为IAT的结束，IAT只有一个函数，也可以不填，填一下 
	memcpy(&exebuffer[rel_current_index+50+20+18],&IAT_RVA,4);
	//把IDT表正式写入 
	memcpy(&exebuffer[rel_current_index],&new_IDT_entry,20);
	printf("hack succesfully, open %s now!\n",argv[1]); 
	 
	free(section_delta_offset);
	free(the_section_header);
	rewind(fp);//指向文件开头 
	fwrite(exebuffer,1,filesize,fp);
	free(exebuffer);
	fclose(fp);
	return 0;
}
