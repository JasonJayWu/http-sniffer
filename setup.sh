# Install libpcap-dev dependency
sudo apt-get update
sudo apt-get install libpcap-dev

# Compile project code to commence HTTP sniffing
gcc –o project_1 project_1.c -lpcap