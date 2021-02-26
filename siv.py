import sys
import textwrap
from datetime import datetime # For using time and date.
from grp import getgrgid # grp library in Python provides access to the Unix group database.
import argparse
import hashlib # Encrypting/Decrypting for hash function.
import json
import os # For working with directories in any environment such as windows, linux or mac.
import pwd  # check current working directory


def siv_init_verify():   

    print("\nWelcome to my simple SIV program implemented in PYHTON. Make sure to run the code over the python version3 in linux...\n")

    # argparse is an python library which offer command-line executable.
    # The textwrap is abling to run a command-line in specific order. 
    parser = argparse.ArgumentParser()
    
    arg_group = parser.add_mutually_exclusive_group()
    
    arg_group.add_argument("-i", "--initialize", action="store_true", help="Initialization mode") # -i, indicationg initialize 
    
    arg_group.add_argument("-v", "--verify", action="store_true", help="Verification mode") # -v, indicating verify
    
    parser.add_argument("-D", "--monitored_directory", type=str, help="Write the directory you want to control") # -D inidicating interested directory to monitor and it should be "string"
    
    parser.add_argument("-V", "--verification_file", type=str,help="Write a name for Verification File that can store information of files in the monitored directory")
    
    parser.add_argument("-R", "--report_file", type=str, help="Give a name for Report File to store final report") # -R indicating the name of report file and should be "string"
    
    parser.add_argument("-H", "--hash_function", type=str, help="Write algorithm, hash supported are 'SHA-1' and 'MD-5' ") # -H indicating type of hash and it should be "string"

   
    args = parser.parse_args()
    
    # Defining a new parameter instead of args.monitored_directory just to simplizing
    _monitor = args.monitored_directory 
    _verification = args.verification_file
    _report = args.report_file
    _algorithm = args.hash_function

                        ##################### initialize mode ######################

    if args.initialize: # Initialization mode
        
        print("Initialization Mode\n")
        startTime = datetime.utcnow()

        if os.path.isdir(_monitor) == 1:  # Check if Monitored directory exists
            print(f"{_monitor} Directory is available...")


            
            if _algorithm == "SHA-1" or _algorithm == "MD-5": # Check the algorithm requested for hashing

                f = 0  # Number of files parsed
                d = 0  # Number of directories parsed
                my_directory = [] # define directory as a list to be able to append easily.
                in_file = {} # define file as a dictionary.
                in_hash = {} # define hash as a dictionary.
                in_dir = {} # define directory as dictionary.

                # Check if Verification and Report files exits. 
                # os.path.isfile return true if available and false if not available.
                if os.path.isfile(_verification) == 1 and os.path.isfile(_report) == 1: 
                    print("Verification and Report files are available\n")

                
            
                # Check if Verification and Report files are outside monitored directory
                    if (os.path.commonprefix([_monitor, _verification]) == _monitor) or (os.path.commonprefix([_monitor, _report]) == _monitor):
                        print("Verification and Report file must be outside the monitored directory\n")
                        sys.exit()

                    else:
                        print("Verification and Report files are outside monitored directory \n")


                else:
                    os.open(_verification, os.O_CREAT, mode=0o777)  # Accessibility permission
                    os.open(_report, os.O_CREAT, mode=0o777)    # octal value of 0o777 is equal to chmod 511 
                    print("Verification or Report file were not available and but it is created now\n")

                    # Check if Verification and Report files are outside monitored directory
                    if (os.path.commonprefix([_monitor, _verification]) == _monitor) or (os.path.commonprefix([_monitor, _report]) == _monitor):
                        print("Verification and Report file must be outside the monitored directory\n")
                        sys.exit()

                    else:
                        print("Verification and Report files are outside monitored directory\n")

                # Ask user whether to overwrite Verification or report files otherwise exit
                user_choice = input ("Would you like to overwrite on this file? yes/no: ")

                if user_choice == "no": # If input == no, exit the system
                    sys.exit()

                elif user_choice == "yes":

                    for subdir, dirs, files in os.walk(_monitor): # Goes inside the monitored directory with a for loop
                                                                  # to record any file and folders in it.

                        for i in dirs: # Record the following values of directory inside the monitored directory.
                                       # Such as, time, size, permision and user.
                            f += 1
                            path = os.path.join(subdir, i)
                            modification_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                            access = oct(os.stat(path).st_mode & 0o777) # octal value of 0o777 is equal to chmod 511            
                            size = os.path.getsize(path)
                            user = pwd.getpwuid(os.stat(path).st_uid).pw_name
                            group = getgrgid(os.stat(path).st_gid).gr_name
                            # Save the Key:Values in a dictionary (in_dir)
                            in_dir[path] = {"Last Modification Time": modification_time, "Accessibility": access, "Size": size, "User": user, "Group":group}

                    
                        for file in files: # Goes inside the file in monitored directory to record the following values.

                            d += 1
                            first_path = os.path.join(subdir, file)
                            first_modification_time = datetime.fromtimestamp(os.stat(first_path).st_mtime).strftime('%c') # Record initialize time and date
                            first_access = oct(os.stat(first_path).st_mode & 0o777) # octal value of 0o777 is equal to chmod 511
                            first_size = os.stat(first_path).st_size
                            first_user = pwd.getpwuid(os.stat(first_path).st_uid).pw_name
                            first_group = getgrgid(os.stat(first_path).st_gid).gr_name
                        
                            # Message digest computed with MD-5
                            if _algorithm == "MD5":
                                # hash mode for encrypting the recorded files "MD-5"
                                hash_type = "md5"
                                h = hashlib.md5()
                                with open(first_path, 'rb') as myfile: # Open the file for reading only in binary mode
                                    buffer = myfile.read()
                                    h.update(buffer)
                                    message = h.hexdigest() # Containing only hexadecimal digits. 

                            # Message digest computed with SHA-1
                            else:
                                # hash mode for encrypting the recorded files "SHA-1" 
                                in_hash = {"hash_type": hash_type}
                                hash_type = "sha1"
                                h = hashlib.sha1()
                                with open(first_path, 'rb') as myfile: # Open the file for reading only in binary mode
                                    buffer = myfile.read()
                                    h.update(buffer)
                                    message = h.hexdigest()
                            # Save the Key:Values in a dictionary (in_file)
                            in_file[first_path] = {"Last Modification Time": first_modification_time , "Accessibility": first_access, "Size": first_size, "User": first_user, "Group": first_group, "hash_type": message}

                    my_directory.append(in_dir)

                    #in_hash = {"hash_type": hash_type}

                    my_directory.append(in_file)
                    my_directory.append(in_hash)
                    json_string = json.dumps(my_directory, indent=4, sort_keys=True) # For pretty printing using sort key and indent. 
                    print("\nVerification File is created")

                    # Write into Verification file
                    with open(_verification, "w") as writefile:

                        writefile.write(json_string)
                    print("\nReport File is now created")

                    # Write into Report file
                    with open(_report, "w") as writefile:

                        end_time = datetime.utcnow()
                        writefile.write("__" * 1000)
                        writefile.write(" ************ Initialization mode completed ************ ")
                        writefile.write("__" * 1000)
                        writefile.write(f"\n\nMonitored directory >> ------------- {_monitor}")
                        writefile.write(f"\nVerification file >> ------------- {_verification}")
                        writefile.write(f"\nNumber of directories parsed >> ------------- "+ str(f))
                        writefile.write("\nNumber of files parsed >> ------------- "+ str(d))
                        writefile.write("\nTime taken >> ----------- "+ str(end_time - startTime) + "\n")
                else:
                    print("Invalid input, You must write yes/no")
                    sys.exit()

            else:
                print("Hash type is not supported. Only MD-5 and SHA-1 is supported.")
                sys.exit()
                        
        else:
            print("Monitored directory is NOT available.")
            sys.exit()
        
            
        
    elif args.verify:

                    ###################### Verification Mode #######################

        startTime = datetime.utcnow() # Recording date and time for verification.
        print("Verification Mode\n")


        if os.path.isfile(_verification) == 1: # Return true if verification file is created.
            print("Verification File is available\n")

            # Check if Verification and Report files are outside monitored directory
            if (os.path.commonprefix([_monitor, _verification]) == _monitor) or (os.path.commonprefix([_monitor, _report]) == _monitor):
                print("Verification and Report file must be outside monitor directory...\n")
                sys.exit()

            else:
                print("Verification and Report files are outside monitored directory\n")

        else:
            print("Verification file is not available")
            sys.exit()

        f = 0  # Number of parsed directories.
        d = 0  # Number of files parsed.
        k = 0  # Number of warnings for monitored directories.

        with open(_verification) as input_file:
            json_decode = json.load(input_file)

        for each_file in json_decode[2]:
            hash_type = each_file[2]


        with open(_report, "a") as report_write:

            for subdir, dirs, files in os.walk(_monitor):
                # The following information extracted from monitored directory.
                for fds in dirs:
                    f += 1
                    path = os.path.join(subdir, fds)
                    size = os.stat(path).st_size
                    user = pwd.getpwuid(os.stat(path).st_uid).pw_name
                    group = getgrgid(os.stat(path).st_gid).gr_name
                    modification_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                    access = oct(os.stat(path).st_mode & 0o777)
                    
                    print(f"Directory >> {path}\n")

                    if path in json_decode[0]: # [0] index means path, [1] means file, [2] means folder.

                        if size != json_decode[0][path]['Size']: # Check if size is changed in comparison with initial one.
                            report_write.write(f"\WARNING... Directory {path} has a different size\n", indent=5)
                            k = k+1
                        if user != json_decode[0][path]['User']: # Check if user is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... Directory {path} has a different user \n", indent=5)
                            k = k+1
                        if group != json_decode[0][path]['Group']: # Check if group is changed in comparison with initial one.
                            report_write.write(f"\n...WARNING... Directory {path} has a different group\n", indent=5)
                            k = k+1
                        if modification_time != json_decode[0][path]['Last Modification Time']: # Check if time of modification is changed in comparison with initial one.
                            report_write.write(f"\n...WARNING... Directory {path} has a different modification date\n")
                            k = k+1
                        if access != json_decode[0][path]['Accessibility']: # Check if access is changed in comparison with initial one.
                            report_write.write(f"\n...WARNING... Directory {path} has changed the access permission\n", indent=5)
                            k = k+1
                    else:
                        report_write.write(f"\n...WARNING... Directory {path} has been added\n", indent=5)
                        k = k+1

            # check if any file or folder added to monitored path.
            for each_prev_dir in json_decode[0]:

                if os.path.isdir(each_prev_dir) == 0:
                    report_write.write(f"\n...WARNING... Directory {each_prev_dir} has been removed\n")
                    k = k+1

            for subdir, dirs, files in os.walk(_monitor): # We goes inside the monitored directory to see 
                                                          # from top to down.
                for file in files:
                    d += 1
                    first_path = os.path.join(subdir, file)
                    first_size = os.stat(first_path).st_size
                    first_user = pwd.getpwuid(os.stat(first_path).st_uid).pw_name
                    first_group = getgrgid(os.stat(first_path).st_gid).gr_name
                    first_modification_time = datetime.fromtimestamp(os.stat(first_path).st_mtime).strftime('%c')
                    first_access = oct(os.stat(first_path).st_mode & 0o777)
                    
                    
                    print(f" ----- File ----- {first_path}    is recorded successfully ...")
                    

                    if hash_type == "md-5":  # Message digest computed with MD-5
                        h = hashlib.md5()
                        with open(first_path, 'rb') as mfile:
                            buffer = mfile.read()
                            h.update(buffer)
                            message = h.hexdigest()

                
                    else:       # Message digest computed with SHA-1
                        h = hashlib.sha1()
                        with open(first_path, 'rb') as hfile:
                            buffer = hfile.read()
                            h.update(buffer)
                            message = h.hexdigest()

                    if first_path in json_decode[1]: # Index [1] means file.

                        if first_size != json_decode[1][first_path]['Size']: # Check if size is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} is changed in size\n")
                            k += 1
                        if first_user != json_decode[1][first_path]['User']: # Check if user is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} has a different user\n")
                            k += 1
                        if first_group != json_decode[1][first_path]['Group']: # Check if group is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} has a different group\n")
                            k += 1
                        if first_modification_time != json_decode[1][first_path]['Last Modification Time']: # Check if modification time is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} has a different modification date or time\n")
                            k += 1
                        if first_access != json_decode[1][first_path]['Accessibility']: # Check if access is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} has modified accessibility permission\n")
                            k += 1
                        if message != json_decode[1][first_path]['hash_type']: # Check if encryption methode is changed in comparison with initial one.
                            report_write.write(f"\nWARNING... File {first_path} has a change in its content\n")
                            k += 1
                    else:
                        report_write.write(f"\nWARNING... Directory {first_path} has been added\n")
                        k += 1

            for each_prev_file in json_decode[1]:
                if os.path.isfile(each_prev_file) == 0: # Return false if file is not available or may removed.
                    report_write.write("\nWARNING... Directory " + each_prev_file + " has been deleted\n")
                    k += 1

        # The Following information is extracted and write in report file.
        with open(_report, "a") as writefile:
            end = datetime.utcnow()
            writefile.write("__" * 1000)
            writefile.write(" ************ Verification mode completed ************ ")
            writefile.write("__" * 1000)
            writefile.write(f"\n\nMonitored directory >> ------------- {_monitor}")
            writefile.write(f"\n\nVerification File >> ------------- {_verification}")
            writefile.write("\n\nNumber of directories parsed >> ------------- " + str(f))
            writefile.write("\n\nNumber of files parsed >> ------------- " + str(d))
            writefile.write("\n\nTotal Warnings = " + str(k))
            writefile.write("\n\nTime taken = " + str(end - startTime))
            writefile.write("\n\nVerification report saved in report file \n")
            writefile.write("__" * 1000)

        print("\nReport File is Created and final reports has written in it ...")
        print(f"\nDone ... Totally {d} files is recorded successfully.\n")

siv_init_verify()
