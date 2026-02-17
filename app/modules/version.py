import lief
from . import colors

def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "VERSION INFO", " -------------------------------") + colors.DEFAULT))
    
    try:
        binary = lief.parse(malware)
        if not binary:
            print((colors.RED + "[X] Not a valid PE file" + colors.DEFAULT))
            csv.write("0")
            return

        version_found = False
        
        # Try multiple methods to get version info
        try:
            # Method 1: Check resources
            if binary.has_resources:
                for resource in binary.resources:
                    if hasattr(resource, 'type') and resource.type == lief.PE.RESOURCE_TYPES.VERSION:
                        version_found = True
                        print((colors.YELLOW + "[+] Version resource found" + colors.DEFAULT))
                        
                        # Try to extract version info
                        if hasattr(resource, 'version_info'):
                            version_info = resource.version_info
                            if version_info:
                                for key, value in version_info.items():
                                    print(f"    {key}: {value}")
                        
                        # Try to get string table
                        if hasattr(resource, 'string_file_info'):
                            string_info = resource.string_file_info
                            if string_info:
                                print((colors.WHITE + "\n    String File Info:" + colors.DEFAULT))
                                for key, value in string_info.items():
                                    print(f"        {key}: {value}")
        except Exception as e:
            print(f"    Error parsing resources: {str(e)}")
        
        # Method 2: Check version info from header
        try:
            if hasattr(binary, 'version_info') and binary.version_info:
                version_found = True
                print((colors.YELLOW + "\n[+] Version Info from header:" + colors.DEFAULT))
                version_info = binary.version_info
                if hasattr(version_info, 'major'):
                    print(f"    Major: {version_info.major}")
                if hasattr(version_info, 'minor'):
                    print(f"    Minor: {version_info.minor}")
                if hasattr(version_info, 'build'):
                    print(f"    Build: {version_info.build}")
        except:
            pass
        
        # Method 3: Check debug information
        try:
            if binary.has_debug:
                for debug in binary.debug:
                    if hasattr(debug, 'version') and debug.version:
                        version_found = True
                        print((colors.YELLOW + "\n[+] Debug Version Info:" + colors.DEFAULT))
                        version = debug.version
                        if hasattr(version, 'major'):
                            print(f"    Major: {version.major}")
                        if hasattr(version, 'minor'):
                            print(f"    Minor: {version.minor}")
        except:
            pass

        if not version_found:
            print((colors.RED + "[X] No version information found" + colors.DEFAULT))
            csv.write("0")
        else:
            csv.write("1")
            
    except Exception as e:
        print((colors.RED + f"[X] Error analyzing version: {str(e)}" + colors.DEFAULT))
        csv.write("0")
