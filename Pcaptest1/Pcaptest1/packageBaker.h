class Package{
private:


	int section_number;
	int section_startIndex[11];
public:
	int length;
	char * data;
	Package(){
		data=NULL;
		length=0;
		section_number=0;
	}
	void create(int len){
		length=len;
		data=new char[length];
		section_number=0;
		section_startIndex[0]=0;
		for(unsigned int i=1;i<11;i++){
			section_startIndex[i]=len;
		}
	}
	char * getSection(unsigned int index){
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
	char * fillSection(unsigned int index,int len){
		if(index>=section_number)section_number=index+1;
		section_startIndex[index+1]=section_startIndex[index]+len;
		return getSection(index);
	}
	char * addSection(int len){
		if(section_number>=10)return NULL;
		unsigned int index=section_number;
		section_number++;
		fillSection(index,len);
	}
};