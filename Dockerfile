FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# 1) ตั้งค่า PATH ให้ครอบคลุมทั้ง Go และ Python scripts
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/opt/XSStrike

# 2) ลง Golang, Python และ Tools พื้นฐาน
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    golang \
    build-essential \
    git \
    ca-certificates \
    jq \
    python3 \
    python3-pip \
    sqlmap \
    whatweb \
    ffuf \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 3) ติดตั้ง Katana (CGO Enabled)
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# 4) ติดตั้ง Nuclei และ Update Templates
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && /root/go/bin/nuclei -update-templates

# 5) ติดตั้ง XSStrike และทำ Symlink ให้เรียกใช้คำสั่ง 'xsstrike' ได้เลย
RUN git clone https://github.com/s0md3v/XSStrike /opt/XSStrike \
    && cd /opt/XSStrike \
    && pip install -r requirements.txt --break-system-packages \
    && chmod +x xsstrike.py \
    && ln -s /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike

# 6) ทำ Symlink ให้ Katana และ Nuclei (กันเหนียวเรื่อง PATH)
# RUN ln -s /root/go/bin/katana /usr/local/bin/katana \
#     && ln -s /root/go/bin/nuclei /usr/local/bin/nuclei

CMD ["/bin/bash"]