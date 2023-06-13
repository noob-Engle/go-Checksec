package main

import (
    "debug/pe"
    "fmt"
    "os"
    "flag"
)

const (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE              = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT                 = 0x0100
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA           = 0x0020
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY           = 0x0080
    IMAGE_DLLCHARACTERISTICS_GUARD_CF                  = 0x4000
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER              = 0x1000
    IMAGE_OPTIONAL_HEADER_MAGIC64                       = 0x20b
    IMAGE_SUBSYSTEM_WINDOWS_GUI                         = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI                         = 3
)

func checkSecurity(file string) error {
    f, err := os.Open(file)
    if err != nil {
        return err
    }
    defer f.Close()

   
    peFile, err := pe.NewFile(f)
    if err != nil {
        return err
    }

    var optionalHeader interface{}

    
    switch oh := peFile.OptionalHeader.(type) {
    case *pe.OptionalHeader32:
        optionalHeader = oh
    case *pe.OptionalHeader64:
        optionalHeader = oh
    default:
        return fmt.Errorf("optional header is not a pe.OptionalHeader32 or pe.OptionalHeader64")
    }

   
    switch oh := optionalHeader.(type) {
    case *pe.OptionalHeader32:
        fmt.Println("ASLR enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
        fmt.Println("DEP enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0)
        fmt.Println("PIE enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
    case *pe.OptionalHeader64:
        fmt.Println("ASLR enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
        fmt.Println("DEP enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0)
        fmt.Println("PIE enabled:", oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
    }

   
    characteristics := peFile.Characteristics
    fmt.Println("GuardCF enabled:", (characteristics&IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0)
    fmt.Println("AppContainer enabled:", (characteristics&IMAGE_DLLCHARACTERISTICS_APPCONTAINER) != 0)

    switch oh := optionalHeader.(type) {
    case *pe.OptionalHeader32:
        fmt.Println("HighEntropyVA enabled:", (oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0)
        fmt.Println("ForceIntegrity enabled:", (oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0)
    case *pe.OptionalHeader64:
        fmt.Println("HighEntropyVA enabled:", (oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0)
        fmt.Println("ForceIntegrity enabled:", (oh.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0)
    }

    // 检查子系统类型
    switch peFile.FileHeader.Characteristics & pe.IMAGE_FILE_DLL {
    case 0:
        fmt.Println("Subsystem type: Native")
    default:
        fmt.Println("Subsystem type: Windows")
    }

    return nil
}

func main() {
    //flag.Parse()
    //file := flag.Arg(0)
    //if err := checkSecurity(file); err != nil {
       // fmt.Println("Error checking security:", err)
    //}

fmt.Println("====================================================================================")
banner := ` ██       ██ ██           ████████                   ██████  ██              ██    
░██      ░██░░           ██░░░░░░                   ██░░░░██░██             ░██    
░██   █  ░██ ██ ███████ ░██         █████   █████  ██    ░░ ░██       █████ ░██  ██
░██  ███ ░██░██░░██░░░██░█████████ ██░░░██ ██░░░██░██       ░██████  ██░░░██░██ ██ 
░██ ██░██░██░██ ░██  ░██░░░░░░░░██░███████░██  ░░ ░██       ░██░░░██░███████░████  
░████ ░░████░██ ░██  ░██       ░██░██░░░░ ░██   ██░░██    ██░██  ░██░██░░░░ ░██░██ 
░██░   ░░░██░██ ███  ░██ ████████ ░░██████░░█████  ░░██████ ░██  ░██░░██████░██░░██
░░       ░░ ░░ ░░░   ░░ ░░░░░░░░   ░░░░░░  ░░░░░    ░░░░░░  ░░   ░░  ░░░░░░ ░░  ░░`
fmt.Println(banner)
fmt.Println("====================================================================================")
fmt.Println("-----------------------------------")
fmt.Println("name: nood|IFNO:Windows Safe Chek|")
fmt.Println("-----------------------------------")

fmt.Println("******************************************")
fmt.Println("                  Check                                           ")
fmt.Println("******************************************")
fileFlag := flag.String("f", "", "PE file to check")
    flag.Parse()

    if *fileFlag == "" {
        flag.PrintDefaults()
        return
    }

    if err := checkSecurity(*fileFlag); err != nil {
        fmt.Println("Error checking security:", err)
    }
}
