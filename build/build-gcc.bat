@echo off

cd ..

:: x64
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -fno-stack-protector -municode -o dist/gravememory64.exe src/gravememory.c -ladvapi32 -lshell32
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -fno-stack-protector -shared -o dist/gravememorydll64.dll src/gravememory_core.c src/gravememory_record.c -ladvapi32 -lrpcrt4

:: x86
i686-w64-mingw32-gcc -O2 -Wall -Wextra -fno-stack-protector -municode -o dist/gravememory32.exe src/gravememory.c -ladvapi32 -lshell32
i686-w64-mingw32-gcc -O2 -Wall -Wextra -fno-stack-protector -shared -o dist/gravememorydll32.dll src/gravememory_core.c src/gravememory_record.c -ladvapi32 -lrpcrt4

pause