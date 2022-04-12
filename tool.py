#from array import _unicodeTypeCode
import requests
import re
import hashlib
import io
import pefile
import struct
import os
import os.path
import time

print('\n')
print(' \t=============Malware Analysis Using Python Script========')
print("\nThis tool will scan the windows EXE files and prepare the following reports:")
print("\n1.Basic Analysis") 
print("\n2.Portable Executable Analysis")
print("\n3.DLLS Reports")       

def convert_bytes(num):
    """
    this function will convert bytes to MB.... GB... etc
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(file_path):
    """
    this function will return the file size
    """
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)


try:
##### Asking For File#####
    f = input("\nEnter path of the file  which you want to scan :- ")

    # print('\n')
    # try:
    #     fp = open(f)
    #     fp.close()
    #     key = ""  # <= Here Enter Your VT API Key between double quotes
    # except IOError:
    #     print("\n [-] There is a no file like '", f, "'")
    #     exit()

    # print('\n\n')


# Image Type Anlaysis
    print('--------------------.')
    print(' [*] Basic Analysis |')
    print('--------------------`')
    print('\n')
    IMAGE_FILE_MACHINE_I386=332
    IMAGE_FILE_MACHINE_IA64=512
    IMAGE_FILE_MACHINE_AMD64=34404

    fl=open(f, "rb")

    s=fl.read(2)
    if s != "MZ":
        print(" Not an EXE file")
    else:
        fl.seek(60)
        s=fl.read(4)
        header_offset=struct.unpack("<L", s)[0]
        fl.seek(header_offset+4)
        s=fl.read(2)
        machine=struct.unpack("<H", s)[0]

        if machine == IMAGE_FILE_MACHINE_I386:
            print(" Image Type = IA-32 (32-bit x86)")
            fp=open('PE Analysis.txt', 'a')
            fp.write("Image Type = IA-32 (32-bit x86)")
            fp.write('\n\n')
            fp.close()
        elif machine == IMAGE_FILE_MACHINE_IA64:
            print(" Image Type = IA-64 (Itanium)")
            fp=open('PE Analysis.txt', 'a')
            fp.write("Image Type = IA-64 (Itanium)")
            fp.write('\n\n')
            fp.close()
        elif machine == IMAGE_FILE_MACHINE_AMD64:
            print(" Image Type = AMD64 (64-bit x86)")
            fp=open('PE Analysis.txt', 'a')
            fp.write("Image Type = AMD64 (64-bit x86)")
            fp.write('\n\n')
            fp.close()
        else:
            print(" Unknown architecture")

        print('\n File Size = ' + file_size(f))
        print('\n Last Modified Date = %s' % time.ctime(os.path.getmtime(f)))
        print('\n Created Date = %s' % time.ctime(os.path.getctime(f)))

        fp=open('PE Analysis.txt', 'a')
        fp.write('File Size = ' + file_size(f))
        fp.write('\n\nLast Modified Date: %s' %
                 time.ctime(os.path.getmtime(f)))
        fp.write('\n\nCreated Date: %s' % time.ctime(os.path.getctime(f)))
        fp.write('\n')
        fp.write('\n')
        fp.close()
    fl.close()



# PE File Analysis"
    try:
        print("\n\n-----------------.")
        print (' [*] PE Analysis |')
        print ('-----------------`')
        pe=pefile.PE(f)
        print ('\n ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase))
        print ('\n Address Of EntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        print ('\n Number Of RvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes))
        print ('\n Number Of Sections = ' + hex(pe.FILE_HEADER.NumberOfSections))

        fp=open('PE Analysis.txt', 'a')

        fp.write('ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase))
        fp.write('\n\nAddress Of EntryPoint = ' + \
                 hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        fp.write('\n\nNumber Of RvaAndSizes = ' + \
                 hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes))
        fp.write('\n\nNumber Of Sections = ' + \
                 hex(pe.FILE_HEADER.NumberOfSections))
        fp.write('\n')
        fp.write('\n')

        # List Import Sections"
        print ('\n [*] Listing Sections...\n')
        fp.write('\n')
        fp.write('\n')
        fp.write('[*] Listing Sections \n\n')

        for section in pe.sections:
            print('\t' + section.Name.decode('utf-8'))
            print("\t\tVirtual Address: " + hex(section.VirtualAddress))
            print("\t\tVirtual Size: " + hex(section.Misc_VirtualSize))
            print("\t\tRaw Size: " + hex(section.SizeOfRawData))
            fp.write('\n ' + section.Name.decode('utf-8'))
            fp.write("\n\n\tVirtual Address: " + hex(section.VirtualAddress))
            fp.write("\n\n\tVirtual Size: " + hex(section.Misc_VirtualSize))
            fp.write("\n\n\tRaw Size: " + hex(section.SizeOfRawData))

            print ('\n')

        # List Import DLL"
        fp.write('\n')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n[*] Listing imported DLLs...')
        fp.write('\n')
        print (' [*] Listing imported DLLs...\n')
        for lst in pe.DIRECTORY_ENTRY_IMPORT:
            print('\n '+lst.dll.decode('utf-8'))
            fp.write('\n'+lst.dll.decode('utf-8'))
            for s in lst.imports:
                print("\t - %s at 0x%08x" %
                      (_UnicodeTypeCode(s.name).decode('utf-8'), s.address))
                fp.write('\n\n' + "\t - %s at 0x%08x" %
                         (pefile.UnicodeStringWrapperPostProcessor(s.name).decode('utf-8'), s.address) + '\n',)


        print ('\n [*] Listing Header Members...')

        fp=open('PE Analysis.txt', 'a')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n[*] Listing Header Members...')
        fp.write('\n')

        for headers in pe.DOS_HEADER.dump():
            print ('\n\t' + headers)
            fp.write('\n')
            fp.write('\n\t' + headers)

        print ('\n')
        fp.close()

        for ntheader in pe.NT_HEADERS.dump():
            print ('\n\t' + ntheader)
            fp=open('PE Analysis.txt', 'a')
            fp.write('\n')
            fp.write('\n\t' + ntheader)

        print ('\n [*] Listing Optional Headers...')

        fp=open('PE Analysis.txt', 'a')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n[*] Listing Optional Headers...')
        fp.write('\n')
        for optheader in pe.OPTIONAL_HEADER.dump():
            print ('\n\t' + optheader)
            fp.write('\n')
            fp.write('\n\t' + optheader)

        print ('\n\n ***********************')
        print (' * See PE Analysis.txt *')
        print (' ***********************')

    except:
        print ('\n [-] ') + f + ' DOS Header magic not found.'



#### Strings Analysis Extracting Atrings From File ####
    print (' \n\n\n\n----------------------.')
    print (' [*] Strings Analysis |')
    print ('----------------------`')
    srt=open(f, "rb")
    data=srt.read()
    unicode_str=re.compile(u'[\u0020-\u007e]{3,}', re.UNICODE)
    myList=unicode_str.findall(data)
    fp=open('strings.txt', 'a')

    for p in myList:
        fp.write(p + '\n')
    fp.close()

    print ('\n\n *******************')
    print (' * See Strings.txt *')
    print (' *******************')
    #### Count Hash Value###
    print ('\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    with io.open(f, mode = "rb") as fd:
        content=fd.read()
        md5=hashlib.md5(content).hexdigest()

    print (' [*] MD5 Hash Value Of Your File Is :- ', md5)
    print ('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


    #####Virus Total Analysis#####

    #####Asking For Key#####
    print( '\n\n\n\n--------------------------.')
    print (' [*] Virus Total Analysis |')
    print ('--------------------------`')

    #####Main Program Function#####
    def main():
        VT_Request(key, md5.rstrip())

    ####Upload Hash On Virus Total####
    def VT_Request(key, hash):

        if len(key) == 64:
            try:
                params={'apikey': key, 'resource': hash}
                url=requests.get(
                    'https://www.virustotal.com/vtapi/v2/file/report', params = params)
                json_response=url.json()
                # print json_response

                response=int(json_response.get('response_code'))
                if response == 0:
                    print('[-] ' + f + ' [' + hash + '] is not in Virus Total')
                    file=open('VT Scan.txt', 'a')
                    file.write('[-] ' + f + ' [' + hash + \
                               '] is not in Virus Total')
                    file.write('\n')
                    file.close()
                elif response == 1:
                    positives=int(json_response.get('positives'))
                    if positives == 0:
                        print('[-] ' + f + ' [' + hash + '] is not malicious')
                        file=open('VT Scan.txt', 'a')
                        file.write(
                            '[-] ' + f + ' [' + hash + '] is not malicious')
                        file.write('\n')
                        file.close()
                    else:

                        sha1=json_response.get('sha1')
                        positives=int(json_response.get('positives'))
                        total=int(json_response.get('total'))
                        sha256=json_response.get('sha256')
                        scans=str(json_response.get('scans'))

                        print ('\n [*] Malware Hit Count ' + str(positives) + '/'+str(total))
                        print ('\n [*] Sha1 Value = ' + sha1)
                        print ('\n [*] Sha256 Value = ' + sha256)
                        # print '\n Scans = ' + str(scans)

                        print (('\n [*] ' + f + ' ['+hash+']' + ' is malicious'))
                        file=open('VT Basic Scan.txt', 'a')
                        file.write(
                            '[*] ' + f + ' [' + hash + '] is malicious.')
                        file.write('\n\n')
                        file.write('\n[*] Malware Hit Count ' + \
                                   str(positives) + '/'+str(total))
                        file.write('\n[*] MD5 Value = ' + md5)
                        file.write('\n[*] Sha1 Value = ' + sha1)
                        file.write('\n[*] Sha256 Value = ' + sha256)
                        file.write('\n\n')
                        file.close()
                        file=open('VT Scan.csv', 'a')
                        file.write(
                            'AV Name,Detection,AV Version,Malware Name,AV Updated Date')
                        file.write('\n')
                        file.write(str(scans).replace('}, u', '\n').replace(' u', '').replace('{', '').replace(': u', ' = ').replace("'", "").replace('}}','').replace(' = detected: ',',').replace('result:','').replace('update:','').replace('uBkav','Bkav') + '\n')
                        file.write('\n')
                        file.close()
                else:
                    print (hash + ' [-] could not be searched. Please try again later.')
                print ('\n\n *******************')
                print (' * See VT Scan.csv *')
                print (' *******************')
            except Exception as e:
                print ('\n [-] Oops!!, Somthing Wrong Check Your Internet Connection')
        else:
            print (" [-] There is something Wrong With Your API Key.")
            exit()

    if __name__ == '__main__':
    	main()

except:
    print('\n\n [-] Oops!, Program Halted')
