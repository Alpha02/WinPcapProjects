class Package{
private:
	unsigned int section_number;
	int section_startIndex[11];
public:
	unsigned int length;
	u_char * data;
	void init(){
		data=NULL;
		length=0;
		section_number=0;
	}
	void create(unsigned int len){
		if(length>0){
			delete [length] data;
		}
		length=len;
		data=new u_char[length];
		section_number=0;
		section_startIndex[0]=0;
		for(unsigned int i=1;i<11;i++){
			section_startIndex[i]=len;
		}
	}
	Package(){
		init();
	}
	Package(unsigned int len){
		init();
		create(len);
	}
	~Package(){
	    delete [length] data;
	}
	u_char * getSection(unsigned int index){
		if(index<section_number){
			return data+section_startIndex[index];
		}
		return NULL;
	}
	int getSectionLength(unsigned int index){
		if(index<section_number){
			return section_startIndex[index+1]-section_startIndex[index];
		}
		return -1;
	}
	u_char * fillSection(unsigned int index,int len){
		if(index>=section_number)section_number=index+1;
		section_startIndex[index+1]=section_startIndex[index]+len;
		return getSection(index);
	}
	u_char * addSection(int len){
		if(section_number>=10)return NULL;
		unsigned int index=section_number;
		section_number++;
		return fillSection(index,len);
	}
};