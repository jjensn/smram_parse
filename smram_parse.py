import sys, os, time, re, shutil
import time
from struct import unpack

SMRAM_SIZE = 0x800000

EFI_SMM_CPU_PROTOCOL_GUID = b'\x97\x6B\x34\xEB\x5F\x97\x9F\x4A\x8B\x22\xF8\xE9\x2B\xB3\xD5\x69'

UEFIDUMP_PATH = r'F:\heckin-usb\MEGAsync\dev\SmmBackdoor.old\UEFIDump.exe'
UEFIDUMP_URL = 'https://github.com/LongSoft/UEFITool/releases/download/A50/UEFIDump_NE_0.1.9_linux_x86_64.zip'

EFIUTILS_PATH = 'ida-efiutils'
EFIUTILS_URL = 'https://github.com/snare/ida-efiutils'

sys.path.append(EFIUTILS_PATH)

# PE format constants
HEADERS_SIZE                                    = 0x400
IMAGE_DOS_HEADER_e_lfanew                       = 0x3c
IMAGE_NT_HEADERS64_OptionalHeader               = 0x18
IMAGE_OPTIONAL_HEADER64_SizeOfCode              = 0x04
IMAGE_OPTIONAL_HEADER64_SizeOfInitializedData   = 0x08
IMAGE_OPTIONAL_HEADER64_AddressOfEntryPoint     = 0x10
IMAGE_OPTIONAL_HEADER64_SizeOfImage             = 0x38

# helper functions for EFI_GUID
guid_parse = lambda data: unpack('=IHHBBBBBBBB', data)
guid_str = lambda guid: '%.8X-%.4X-%.4X-%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X' % guid

_align = lambda val: '%s' % val

# EFI_GUID values not included into ida-efiutils
GUIDs = {

    'SMM_CPU_SYNC_PROTOCOL_GUID':                   [0xd5950985, 0x8be3, 0x4b1c, 0xb6, 0x3f, 0x95, 0xd1, 0x5a, 0xb3, 0xb6, 0x5f],
    'SMM_CPU_SYNC2_PROTOCOL_GUID':                  [0x9db72e22, 0x9262, 0x4a18, 0x8f, 0xe0, 0x85, 0xe0, 0x3d, 0xfa, 0x96, 0x73],
    'EFI_SMM_CPU_SERVICE_PROTOCOL_GUID':            [0x1d202cab, 0xc8ab, 0x4d5c, 0x94, 0xf7, 0x3c, 0xfc, 0xc0, 0xd3, 0xd3, 0x35],
    'PCH_SPI_PROTOCOL':                             [0x56521f06, 0x0a62, 0x4822, 0x99, 0x63, 0xdf, 0x01, 0x9d, 0x72, 0xc7, 0xe1],
    'PCH_TCO_SMI_DISPATCH_PROTOCOL_GUID':           [0x9e71d609, 0x6d24, 0x47fd, 0xb5, 0x72, 0x61, 0x40, 0xf8, 0xd9, 0xc2, 0xa4],
    'PCH_PCIE_SMI_DISPATCH_PROTOCOL_GUID':          [0x3e7d2b56, 0x3f47, 0x42aa, 0x8f, 0x6b, 0x22, 0xf5, 0x19, 0x81, 0x8d, 0xab],
    'PCH_ACPI_SMI_DISPATCH_PROTOCOL_GUID':          [0xd52bb262, 0xf022, 0x49ec, 0x86, 0xd2, 0x7a, 0x29, 0x3a, 0x7a, 0x05, 0x4b],
    'PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL_GUID':   [0x83339ef7, 0x9392, 0x4716, 0x8d, 0x3a, 0xd1, 0xfc, 0x67, 0xcd, 0x55, 0xdb],
    'PCH_SMM_IO_TRAP_CONTROL_PROTOCOL':             [0x514d2afd, 0x2096, 0x4283, 0x9d, 0xa6, 0x70, 0x0c, 0xd2, 0x7d, 0xc7, 0xa5],
    'PCH_ESPI_SMI_DISPATCH_PROTOCOL_GUID':          [0xB3C14FF3, 0xBAE8, 0x456C, 0x86, 0x31, 0x27, 0xFE, 0x0C, 0xEB, 0x34, 0x0C],
    'EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID':           [0xbd88ec68, 0xebe4, 0x4f7b, 0x93, 0x5a, 0x4f, 0x66, 0x66, 0x42, 0xe7, 0x5f],
    'EFI_EC_ACCESS_PROTOCOL_GUID':                  [0x70eeecbe, 0x727a, 0x4244, 0x90, 0x4c, 0xdb, 0x6b, 0xf0, 0x05, 0x53, 0x92],
    'EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID':           [0xbd88ec68, 0xebe4, 0x4f7b, 0x93, 0x5a, 0x4f, 0x66, 0x66, 0x42, 0xe7, 0x5f],
    'EFI_ACPI_DIS_DISPATCH_PROTOCOL_GUID':          [0x9c939ba6, 0x1fcc, 0x46f6, 0xb4, 0xe1, 0x10, 0x2d, 0xbe, 0x18, 0x65, 0x67]
}

class FwImage(object):

    def __init__(self, path = None):

        self.data = {}

        if path is not None:

            if os.path.isdir(path):

                self.data = self.scan_dir(path)

            elif os.path.isfile(path):

                self.data = self.scan_file(path)

    def scan_dir(self, path):

        ret = {}

        for fname in os.listdir(path):
            # check for PE image file
            m = re.match('Section_PE32_image_\w{8}-\w{4}-\w{4}-\w{4}-\w{12}_(\w+)_body.bin', fname)
            if m:                
                image_name = m.group(1).strip()
                if len(image_name) == 0: continue

                # read file contents
                fpath = os.path.join(path, fname)
                fdata = open(fpath, 'rb').read(HEADERS_SIZE)

                # use image info as key and image name as value
                ret.update([( self.image_info(fdata), image_name )])
        return ret

    def scan_file(self, path):

        dir_name = os.path.dirname(path)
        temp_name = 'fw_image_%d' % int(time.time())
        temp_path = os.path.join(dir_name, temp_name)

        print('[+] Copying "%s" to "%s"...' % (path, temp_path))

        # copy firmware image to temporary file
        shutil.copyfile(path, temp_path)

        print('[+] Unpacking "%s"...\n' % temp_path)

        # extract image contents
        print("%s %s" % (UEFIDUMP_PATH, temp_path))
        code = os.system("%s %s" % (UEFIDUMP_PATH, temp_path))
        if code != 0:

            print('WARNING: Error while running %s' % UEFIDUMP_PATH)
            print('You can download UEFIDump here: %s\n' % UEFIDUMP_URL)
            return {}

        else:

            print('')

        # scan contents for PE files
        dump_path = temp_path + '.dump'
        ret = self.scan_dir(dump_path)

        # cleanup
        shutil.rmtree(dump_path)
        os.unlink(temp_path)
        shutil.rmtree(temp_path, True)

        return ret

    def image_info(self, data):

        # read e_lfanew field
        offset = unpack('I', data[IMAGE_DOS_HEADER_e_lfanew : \
                                  IMAGE_DOS_HEADER_e_lfanew + 4])[0]

        offset += IMAGE_NT_HEADERS64_OptionalHeader
                  
        get_field = lambda t, s, o: \
                    unpack(t, data[offset + o : offset + o + s])[0]    

        # read optional header fields
        return ( get_field('I', 4, IMAGE_OPTIONAL_HEADER64_SizeOfCode),
                 get_field('I', 4, IMAGE_OPTIONAL_HEADER64_SizeOfInitializedData),
                 get_field('I', 4, IMAGE_OPTIONAL_HEADER64_AddressOfEntryPoint),
                 get_field('I', 4, IMAGE_OPTIONAL_HEADER64_SizeOfImage) )

    def image_name(self, data):

        # find image name by image info
        try: return self.data[self.image_info(data)]
        except KeyError: return None

class GuidDb(object):

    def __init__(self, guids = None):

        self.guids = {}

        try: 

            import efiguids
            self.load(efiguids.GUIDs)

        except ImportError: pass

        try: 

            import efiguids_ami
            self.load(efiguids_ami.GUIDs)

        except ImportError: pass

        if len(self.guids) == 0:

            print('Error while loading GUIDs from %s' % EFIUTILS_PATH)
            print('You can download ida-efiutils here: %s\n' % EFIUTILS_URL)

        if guids is not None: self.load(guids)

    def load(self, guids):

        _name = lambda n: n[:-5] if n[-5:] == '_GUID' else n

        # load GUID's database from ida-efiutils
        self.guids.update(map(lambda it: ( guid_str(tuple(it[1])), \
                                           _name(it[0]) ), guids.items()))

    def lookup(self, guid):

        # get name by GUID
        try: return self.guids[guid_str(guid)]
        except KeyError: return None

class Dumper(object):

    # helper functions for SMRAM dump
    in_smram = lambda self, addr: addr >= self.smram and addr < self.smram + self.smram_size
    to_offset = lambda self, addr: addr - self.smram
    from_offset = lambda self, offset: offset + self.smram        

    has_guid = lambda self, addr, guid: self.data[self.to_offset(addr) : \
                                                  self.to_offset(addr) + self.image_size(addr)].find(guid) \
                                                  != -1

    def __init__(self, smram_dump, fw_image = None, smram_base = None, smram_size = None):

        self.data = open(smram_dump, 'rb').read()  

        # parse firmware image
        self.fw = FwImage(fw_image)

        # load EFI_GUID database
        self.guids = GuidDb(guids = GUIDs)

        if smram_base is None:
        
            self.smram = unpack('Q', self.data[0x10 : 0x18])[0] & 0xff000000    

        else:

            self.smram = smram_base

        if smram_size is None:

            self.smram_size = SMRAM_SIZE

        else:

            self.smram_size = smram_size

        print('[+] SMRAM is at 0x%x:%x' % (self.smram, self.smram + self.smram_size - 1)) 

    # get image base by address inside of it
    def image_by_addr(self, addr):
        #print(hex(addr)
        offset = self.to_offset(addr)
        #print hex(offset)
        ptr = offset & 0xFFFFFF0
       # print hex(ptr)

        while offset - ptr < 0x100000:

            # check for IMAGE_DOS_HEADER signature

            if self.data[ptr : ptr + 2] == b'MZ':
                #print 'found'
                return self.from_offset(ptr)
            #print hex(ptr)
            ptr -= 0x10

    def image_size(self, addr):        

        offset = self.to_offset(self.image_by_addr(addr))

        # read e_lfanew field
        offset += unpack('I', self.data[offset + IMAGE_DOS_HEADER_e_lfanew : \
                                        offset + IMAGE_DOS_HEADER_e_lfanew + 4])[0]

        offset += IMAGE_NT_HEADERS64_OptionalHeader + \
                  IMAGE_OPTIONAL_HEADER64_SizeOfImage

        # read SizeOfImage field
        return unpack('I', self.data[offset : offset + 4])[0]  

    def image_name(self, addr):
      
        if addr == None:
            return None
        offset = self.to_offset(addr)
        #print hex(offset)
        #print self.fw.image_name(self.data[offset : offset + HEADERS_SIZE])

        return self.fw.image_name(self.data[offset : offset + HEADERS_SIZE])  

    def dump_smst(self):

        # check for EFI_SMM_SYSTEM_TABLE signature
        ptr = self.data.find(b'SMST\0\0\0\0')
        if ptr != -1:

            print('[+] EFI_SMM_SYSTEM_TABLE2 is at 0x%x' % self.from_offset(ptr))

    def dump_images(self):

        print('\nLOADED SMM DRIVERS:\n')

        ptr = 0

        while ptr < len(self.data):

            # check for DOS image header
            if self.data[ptr : ptr + 2] == b'MZ':

                #print('found mz')

                # read e_lfanew field
                offset = unpack('I', self.data[ptr + IMAGE_DOS_HEADER_e_lfanew : \
                                               ptr + IMAGE_DOS_HEADER_e_lfanew + 4])[0] + ptr

                # check for PE image header
                if self.data[offset : offset + 2] == b'PE':

                    addr = self.from_offset(ptr)
                    name = self.image_name(addr)
                    _, _, entry, size = self.fw.image_info(self.data[ptr : ptr + HEADERS_SIZE])

                    print('0x%x: size = 0x%.8x, ep = 0x%x, name = %s' % \
                          (addr, size, self.from_offset(ptr + entry), \
                           _align('' if name is None else name)))

            ptr += 0x100

    def dump_smi_entries(self):

        print('\nSMI ENTRIES:\n')

        #
        # Standard SMI entry stub signature
        #
        ptr = 0
        num = 0

        sig = [ b'\xBB', None, b'\x80',                   # mov     bx, 80XXh
                b'\x66', b'\x2E', b'\xA1', None, b'\xFB',   # mov     eax, cs:dword_FBXX
                b'\x66', None, None,                     # mov     edx, eax
                b'\x66', None, None ]  
        
        #print(type(self.data))                  # mov     ebp, eax
        #print(len(self.data))
        while ptr < len(self.data):

            found = True
            for i in range(len(sig)):

                # check for signature at each 100h offset of SMRAM
                if sig[i] is not None and sig[i] != self.data[ptr + i].to_bytes(1, 'little'):

                    #print(self.data[ptr + i])

                    found = False
                    break

            if found:

                print('CPU %d: 0x%x' % (num, self.from_offset(ptr)))
                num += 1

            ptr += 0x100   

    def dump_protocols(self):  

        first_entry = None
        ptr = 0
        parse = lambda offset: unpack('QQ16sQ', self.data[offset : offset + 0x28])

        while ptr < self.smram_size - 0x100:

            # check for 'prte' signature
            if self.data[ptr : ptr + 4] == b'prte':

                flink, blink, guid, info = parse(ptr + 8)

                # check for valid protocol structure
                if self.in_smram(flink) and self.in_smram(blink) and self.in_smram(info):

                    print('\n[+] Found prte structure at offset 0x%x' % ptr)

                    first_entry = ptr
                    break

            ptr += 8

        if first_entry is None:

            print('\nERROR: Unable to find prte entry')
            return -1 

        print('\nSMM PROTOCOLS:\n')

        entry = first_entry

        # iterate double linked list
        while True:

            flink, blink, guid, info = parse(entry + 8)

            # check for valid protocol structure
            if not self.in_smram(flink) or not self.in_smram(blink):

                print('ERROR: Invalid prte entry at 0x%x' % entry)
                return -1

            # check for protocol information
            if self.in_smram(info):        

                # get protocol information
                offset = self.to_offset(info)
                tmp_1, tmp_2, tmp_3, addr = unpack('QQQQ', self.data[offset : offset + 0x20])

                if self.in_smram(tmp_1) and self.in_smram(tmp_2) and \
                   self.in_smram(tmp_3) and self.in_smram(addr):

                    guid = guid_parse(guid)
                    name = self.guids.lookup(guid)

                    # get image information
                    #print hex(addr)
                    image = self.image_by_addr(addr)
                    #print image
                    
                    image_name = self.image_name(image)
                    image_name = image_name if image_name is not None else '0x%X' % addr

                    print('0x%x: addr = 0x%x, image = %s, guid = %s' % \
                          (self.from_offset(entry), addr, _align(image_name),
                           guid_str(guid) if name is None else name))

            entry = self.to_offset(flink) - 8
            if entry == first_entry: break

    def dump_sw_smi_handlers(self):  

        parse = lambda offset: unpack('QQQQ', 
                               self.data[offset : offset + ((4*8))])

        ptr = 0
        first_entry = None
        while ptr < self.smram_size - 0x100:
          
            # check for 'DBRC' signature
            #print(hex(ptr))
            #exit(1)
            if self.data[ptr : ptr + 4] == b'SWSM' :

                flink, blink, code, func = parse(ptr + 8)

                # check for valid EFI_LIST_ENTRY and SW SMI handler
                if self.in_smram(flink) and self.in_smram(blink):

                    print('\n[+] Found SWSM structure at offset 0x%x' % ptr)

                    first_entry = ptr
                    break

            ptr += 8

        if first_entry is None:

            print('\nERROR: Unable to find DBRC entry')
            return -1 

        print('\nSW SMI HANDLERS:\n')

        entry = first_entry
        known_handlers = []

        while True:
            flink, blink, code, func = parse(entry + 8)
            # check for SW SMI handler information
            if self.in_smram(func) and code >= 0 and code <= 255:    
                if entry not in known_handlers:
                    # get image information
                    print(hex(func))
                    image = self.image_by_addr(func)
                    image_name = self.image_name(image)
                    uses_cpu_prot = self.has_guid(image, EFI_SMM_CPU_PROTOCOL_GUID)

                    print('0x%x: SMI = 0x%.2x, addr = 0x%x, image = %s %s' % \
                          (self.from_offset(entry), code, func, \
                          _align(image_name if image_name is not None else '0x%x' % image), \
                          '*' if uses_cpu_prot else ''))
                    known_handlers.append(entry)

        
            entry = self.to_offset(flink) - 8
      
            if entry == first_entry: 
                #print len(known_handlers)
                break

    def _dump_handlers(self, head):

                                                        # 004A09A0  C0 08 4A 8B 00 00 00 00                     Q
        #           C0 08 4A 8B 00 00 00 00   Q
        # 004A09B0  18 FF 47 8B 00 00 00 00                     Q
        #           00 00 00 00 00 00 00 00   Q
        # 004A09C0  98 08 4A 8B 00 00 00 00                     Q
        #           18 09 4A 8B 00 00 00 00  Q

        # A0 09 4A 8B 00 00 00 00 
        # A0 09 4A 8B 00 00 00 00 
        # 76 DD 99 60 6E BE 15 51

        parse = lambda offset: unpack('QQQ', self.data[offset : offset + 0x18])  
        entry = head

        while True:
            #print len(self.data[entry + 8 : entry + 8 + 0x18])
            flink, blink, func = parse(entry + 8)

            if self.data[entry : entry + 4] == b'smih':
                # print 'good'
                # exit(0)
                image = self.image_by_addr(func)
                image_name = self.image_name(image)

                print('0x%x: addr = 0x%x, image = %s' % \
                      (self.from_offset(entry), func, \
                       image_name if image_name is not None else '0x%x' % image))

            entry = self.to_offset(flink) - 8
            # print hex(flink)
            # print hex(self.to_offset(flink))
            # exit(0)
            if entry == head: break 
        #exit(0)

    def dump_smi_handlers(self):          

        first_entry = None
        ptr =  0
        parse = lambda offset: unpack('QQ16sQQ', self.data[offset : offset + 0x30])    

        while ptr < self.smram_size - 0x100:

            # check for 'smie' signature
            if self.data[ptr : ptr + 4] == b'smie':
                
                flink, blink, guid, h_flink, guid2 = parse(ptr + 8)

                # check for valid EFI_LIST_ENTRY
                if self.in_smram(flink) and self.in_smram(blink) and \
                   self.in_smram(h_flink):

                    print('\n[+] Found smie structure at offset 0x%x' % ptr)

                    first_entry = ptr
                    break

            ptr += 8

        if first_entry is None:

            print('\nERROR: Unable to find smie entry')
            return -1 

        print('\nSMI HANDLERS:\n')

        entry = first_entry
        # iterate double linked list
        while True:
           

        
            # 0xD0, 0x95, 0x7F, 0x8B, 0x00, 0x00, 0x00, 0x00, Q
            # 0x20, 0x6E, 0x4C, 0x8B, 0x00, 0x00, 0x00, 0x00, Q
            # 0x90, 0x8D, 0x9B, 0xEE, 0xA6, 0xC5, 0xA2, 0x40, GUID
            # 0xBD, 0xE2, 0x52, 0x55, 0x8D, 0x33, 0xCC, 0xA1, GUID
            # 0xA0, 0x09, 0x4A, 0x8B, 0x00, 0x00, 0x00, 0x00, Q
            # 0xA0, 0x09, 0x4A, 0x8B, 0x00, 0x00, 0x00, 0x00, Q

            # Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

            # 004A09A0  C0 08 4A 8B 00 00 00 00 
            #           C0 08 4A 8B 00 00 00 00 
            # 004A09B0  18 FF 47 8B 00 00 00 00 
            #           00 00 00 00 00 00 00 00  
            # 004A09C0  98 08 4A 8B 00 00 00 00 
            #           18 09 4A 8B 00 00 00 00  

            # 004A09D0  1E 00 00 00 00 00 00 00 89 4B 1D 19 57 30 F2 A4 
            # 004A09E0  89 4B 1D 19 57 30 F2 A4 8B 6B 1F 39 55 10 F0 84 
            # 004A09F0  70 74 61 6C 5D 10 F8 84 80 00 00 00 00 00 00 00  


            flink, blink, guid, h_flink, h_blink = parse(entry + 8)

            # print flink
            # print blink
            # print guid
            # print hex(h_flink)
            # exit(0)

            # check for valid EFI_LIST_ENTRY
            if not self.in_smram(flink) or not self.in_smram(blink):

                print('ERROR: Invalid smie entry at 0x%x' % entry)
                return -1

            if self.data[entry : entry + 4] == b'smie' and \
               self.in_smram(h_flink) and self.in_smram(h_blink):

                guid = guid_parse(guid)
                name = self.guids.lookup(guid)

                print('0x%x: guid = %s' % (self.from_offset(entry), \
                      guid_str(guid) if name is None else name))

                self._dump_handlers(entry + 0x20)

                print('')

            entry = self.to_offset(flink) - 8
            if entry == first_entry: break 

    def dump_root_smi_handlers(self):          

        first_entry = None
        ptr = 0
        parse = lambda offset: unpack('QQQQ', self.data[offset : offset + 0x20])    

        while ptr < self.smram_size - 0x100:

            # check for 'smie' signature
            if self.data[ptr : ptr + 4] == b'smih' or self.data[ptr : ptr + 4] == b'SMIH':
                
                flink, blink, func, entry = parse(ptr + 8)

                # check for valid EFI_LIST_ENTRY
                if self.in_smram(flink) and self.in_smram(blink) and \
                   self.in_smram(func) and entry == 0:

                    print('\n[+] Found smih structure of root SMI handler at offset 0x%x' % ptr)

                    first_entry = ptr
                    break

            ptr += 8

        if first_entry is None:

            print('\nERROR: Unable to find smih entry')
            return -1 

        print('\nROOT SMI HANDLERS:\n')

        self._dump_handlers(first_entry)

def main():

    if len(sys.argv) <= 1:

        print('USAGE: smram_parse.py <SMRAM_dump> [flash_image_dump [SMRAM_base [SMRAM_size]]]')
        return 0

    d = Dumper(sys.argv[1], \
               fw_image = sys.argv[2] if len(sys.argv) > 2 else None,
               smram_base = int(sys.argv[3], 16) if len(sys.argv) > 3 else None,
               smram_size = int(sys.argv[4], 16) if len(sys.argv) > 4 else None)

    d.dump_smst()

    # show SMI entries information
    d.dump_smi_entries()

    # show loaded images information
    d.dump_images()

    # show SMM protocols information
    d.dump_protocols()

    # show SMI handlers information
    d.dump_sw_smi_handlers()
    d.dump_root_smi_handlers()
    d.dump_smi_handlers()    

    print('\nNOTES:')
    print('\n * - SW SMI handler uses ReadSaveState()/WriteSaveState()\n')

    return 0

if __name__ == '__main__':
    
    sys.exit(main())


