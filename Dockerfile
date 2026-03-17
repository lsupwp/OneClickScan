FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# 1) ตั้งค่า PATH ให้ระบบรู้จัก Folder ที่ Go ติดตั้ง Binary ไว้
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# 2) ลง Golang และ Tools ที่จำเป็นสำหรับการ Compile (CGO)
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    golang \
    build-essential \
    git \
    ca-certificates \
    jq \
    ffuf \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 3) ติดตั้ง Katana (CGO Enabled)
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# 4) ติดตั้ง Nuclei และทำการ Update Templates ทันที
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates

# (ทางเลือก) ทำ Symbolic Link เพื่อให้เรียกใช้จาก /usr/local/bin ได้แบบชัวร์ๆ
# RUN ln -s /root/go/bin/katana /usr/local/bin/katana \
#     && ln -s /root/go/bin/nuclei /usr/local/bin/nuclei

CMD ["/bin/bash"]