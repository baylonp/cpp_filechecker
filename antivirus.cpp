#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdexcept>



#include<vector>

// OpenSSL Library
#include <openssl/sha.h>

//loading...
#include<unistd.h>
#include<stdbool.h>
#include<cstdlib>
#include<pthread.h>




////////////////////FUNZIONE DI HASHING///////////////////////////////////////
inline std::string SHA256(const char* const path){

  std::ifstream fp(path, std::ios::in | std::ios::binary);

  if (not fp.good()) {
    std::ostringstream os;
    os << "Cannot open \"" << path << "\": " << std::strerror(errno) << ".";
    throw std::runtime_error(os.str());
  }

  constexpr const std::size_t buffer_size { 1 << 12 };
  char buffer[buffer_size];

  unsigned char hash[SHA256_DIGEST_LENGTH] = { 0 };

  SHA256_CTX ctx;

  SHA256_Init(&ctx);

  while (fp.good()) {
    fp.read(buffer, buffer_size);
    SHA256_Update(&ctx, buffer, fp.gcount());
  }

  SHA256_Final(hash, &ctx);
  fp.close();

  std::ostringstream os;
  os << std::hex << std::setfill('0');

  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    os << std::setw(2) << static_cast<unsigned int>(hash[i]);
  }
  return os.str();
}/////FINE SHA256

////////////////////FINE FUNZIONE DI HASHING///////////////////////////////////////





///////////////////CLASSE ANTIVIRUS///////////////////////////////////////

class Antivirus{

private:

  typedef std::vector<std::string> contenitore;

  contenitore ShaContainer; //sha256 che sono nel file

public:

  Antivirus(){};

  //Comparer(std::string validità_,contenitore ShaContainer_):validity(validità_),ShaContainer(ShaContainer_){};

  friend inline std::string SHA256(const char* const path);


  Antivirus(const std::string& filename);



  bool Finder(const std::string sha256);

};///////////////////FINE CLASSE ANTIVIRUS///////////////////////////////////////







 Antivirus::Antivirus(const std::string& filename){


  std::ifstream ifs(filename);

  if(!ifs.good()){

    std::cerr<<"Can not open file"<<std::endl;

  };


int num_sha_int=0;

ifs >> num_sha_int;


  if(num_sha_int<=0){

    std::cerr<<"Empty database"<<std::endl;
  };


  ShaContainer.reserve(num_sha_int);

  std::string sha;
  std::getline(ifs,sha); //legge stringa vuota dopo il numero all'interno del file


//popola vettore di stringhe
  for(int i =0; i< num_sha_int;i++ ){

    std::getline(ifs,sha);
    ShaContainer.push_back(sha);

  };


ifs.close();

return ;

};



/////////////FINDER////////////////
bool Antivirus::Finder(const std::string sha256){




    for(int i=0;i<ShaContainer.size();i++){



          if(ShaContainer[i]==sha256){


            return true;
          };

    };

  return false;
  };


/////////////FINE FINDER////////////////



/////////////INIZIO EXTENSION-CHECKER////////////////

bool ExtensionChecker( std::string filetitle){


  std::stringstream s(filetitle);

  std::vector<std::string> estensioni;

  estensioni.push_back("xlsx");
  estensioni.push_back("sh");
  estensioni.push_back("exe");
  estensioni.push_back("bin");
  estensioni.push_back("bat");


  std::string extension;
  getline(s,extension,'.');

  getline(s,extension);
  
  for(int i =0;i<estensioni.size();i++){

      if(estensioni[i]==extension) return true;

  };


return false;


};


/////////////FINE EXTENSION-CHECKER////////////////



///////////////////UPDATE BAR///////

void update_bar(int progress){

  

      int num_chars = progress * 0.3;

      std::cout<<"\r Loading [";
      for(int i=0;i<num_chars; i++){

        std::cout<<"-";


      };

      for(int i=0;i<30-num_chars;i++){

        std::cout<<" ";

      };

      std::cout<<"]";
      fflush(stdout);
};

///////////////////FINE UPDATE BAR////////









int main(int argc, char* argv[]){

std::cout<< R"(


  ███████╗██╗██╗     ███████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗     ██╗   ██╗ ██████╗    ██╗    ██████╗ 
  ██╔════╝██║██║     ██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ██║   ██║██╔═████╗  ███║   ██╔═████╗
  █████╗  ██║██║     █████╗  ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝    ██║   ██║██║██╔██║  ╚██║   ██║██╔██║
  ██╔══╝  ██║██║     ██╔══╝  ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ╚██╗ ██╔╝████╔╝██║   ██║   ████╔╝██║
  ██║     ██║███████╗███████╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║     ╚████╔╝ ╚██████╔╝██╗██║██╗╚██████╔╝
  ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝   ╚═════╝ ╚═╝╚═╝╚═╝ ╚═════╝ 
                                                                          

By: Luca Cremonese,Jacopo Andreucci             Course: Programmazione e Progettazione Software                 Date: 29/07/22


)";




int choice;

do{

std::cout<<"************************************************************* "<<std::endl;
std::cout<<"Options: "<<std::endl;
std::cout<<"  "<<std::endl;
std::cout<<"[1]Scan file(s)"<<std::endl;
std::cout<<"[2]Calculate sha256 of file(s)"<<std::endl;
std::cout<<"[3]Scan file(s) extension"<<std::endl;
std::cout<<"   "<<std::endl;

std::cout<<"Type anything else  to close the program"<<std::endl;

std::cout<<"************************************************************* "<<std::endl;

std::cin>>choice;




  if(choice == 1){     //sha256





        
    std::cout<<std::endl;

        if (argc < 2) {
            std::cerr << "usage: " << argv[0] << " FILE_1 [FILE_2 [... [FILE_N]]]" << std::endl;
            return 0;
            
        }



    std::cout<< R"(

          
)";   
      ///////////////////PROGRESS BAR///////

      for(int i=0;i<=100; i++){

        update_bar(i);
        usleep(20000);

      };

      std::cout<<"100%"<<std::endl;

    ///////////////////FINE PROGRESS BAR///////

    std::cout<< R"(


)";
    std::cout<< R"(

[Results]

)";


        std::vector<std::string> stringhe256_calcolate;

        for (int arg = 1; arg < argc; ++arg) {
            try {

            stringhe256_calcolate.push_back(SHA256(argv[arg]));//popola il vettore di stringhe stringhe256_calcolate, cioè tutti gli sha256 dei file 

            std::cout <<"sha256: "<<SHA256(argv[arg]) << " " << argv[arg] << std::endl;
            std::cout<<"   "<<std::endl;
            } catch(const std::exception& e) {
            std::cerr << "[fatal] " <<  e.what() << std::endl;

                std::cout<<std::endl;
            };
        };







      //std::vector<std::string> stringhe;

      Antivirus a("file_di_sha.txt");

      int i=0;

      while(i<stringhe256_calcolate.size()){

            //chiama metodo per trovare la sha nel database
          bool variabile = a.Finder(stringhe256_calcolate[i]);



            if(variabile){

              std::cout<<"Found: "<<argv[i+1]<<"("<<stringhe256_calcolate[i]<<")"<<" is infected!"<<std::endl;

              std::cout<<std::endl;

            }else{

              std::cout<<"Not found in database: "<<argv[i+1]<<" is clean"<<std::endl;

              std::cout<<std::endl;

            };


        i++;
      };



    }else if(choice==2){
    std::cout<< R"(

          
)";      

        ///////////////////PROGRESS BAR///////

      for(int i=0;i<=100; i++){

        update_bar(i);
        usleep(20000);

      };

      std::cout<<"100%"<<std::endl;

    ///////////////////FINE PROGRESS BAR///////
    std::cout<< R"(

         
)";
    std::cout<< R"(

[Results]

)";


        for (int arg = 1; arg < argc; ++arg) {
            try {

            std::cout<<"sha256: " << SHA256(argv[arg]) << " " << argv[arg] << std::endl;
            std::cout<<"  "<<std::endl;
            } catch(const std::exception& e) {
            std::cerr << "[fatal] " <<  e.what() << std::endl;

          std::cout<<std::endl;
            }
        }





    }else if(choice==3){
     std::cout<< R"(

          
)";     

      ///////////////////PROGRESS BAR///////

      for(int i=0;i<=100; i++){

        update_bar(i);
        usleep(15000);

      };

      std::cout<<"100%"<<std::endl;

    ///////////////////FINE PROGRESS BAR///////
    std::cout<< R"(

          
)";
    std::cout<< R"(

[Results]

)";



    int i=1;

    while(i<argc){


          bool temp= ExtensionChecker(argv[i]);

          if(temp) {

          std::cout<<argv[i]<<": "<<"File-extension has been found among evil extensions, be careful"<<std::endl;

          std::cout<<std::endl;
          i++;

          

        }else{

          std::cout<<argv[i]<<": "<<"File-extension has NOT been found among evil extensions, we advise a proper sha256 scan anyway"<<std::endl;
          std::cout<<std::endl;
          
          i++;

          

        };



    };



    };

}while(choice==1 || choice ==2 || choice ==3);

  return 0;
}