FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# 1) ตั้งค่า PATH ให้ครอบคลุมทั้ง Go และ Scripts ต่างๆ
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/opt/XSStrike

# 2) ลง Dependencies พื้นฐาน (รวม python3-pip เรียบร้อย)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    golang \
    build-essential \
    git \
    ca-certificates \
    jq \
    python3 \
    python3-pip \
    python3-setuptools \
    sqlmap \
    nmap \
    whatweb \
    subfinder \
    ffuf \
    seclists \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 3) ติดตั้ง Katana (CGO Enabled), httpx และ Nuclei
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 4) Update Nuclei Templates
RUN /root/go/bin/nuclei -update-templates

# 5) ติดตั้ง XSStrike พร้อมทำ Symlink ให้เรียกใช้คำสั่ง 'xsstrike' ได้เลย
RUN git clone https://github.com/s0md3v/XSStrike /opt/XSStrike && \
    cd /opt/XSStrike && \
    # ใช้ pip3 ติดตั้ง requirements
    pip3 install -r requirements.txt --break-system-packages && \
    # เพิ่ม Shebang เพื่อให้รันได้เหมือนโปรแกรมปกติ
    sed -i '1i #!/usr/bin/env python3' xsstrike.py && \
    chmod +x xsstrike.py && \
    ln -s /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike

WORKDIR /root
CMD ["/bin/bash"]