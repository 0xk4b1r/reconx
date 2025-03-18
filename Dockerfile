FROM ubuntu:22.04

LABEL maintainer="@0xk4b1r"
LABEL version="1.0.0"
LABEL description="Docker image for reconX - A comprehensive reconnaissance framework"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /opt/reconx

# Copy only the installation script first to leverage Docker caching
COPY install.py /opt/reconx/

# Install essential packages and update system
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    git \
    wget \
    curl \
    unzip \
    tar \
    build-essential \
    libpcap-dev \
    sudo \
    nmap \
    whatweb \
    nikto \
    masscan \
    golang \
    nodejs \
    npm \
    ruby \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Chrome for Aquatone
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get update \
    && apt-get install -y ./google-chrome-stable_current_amd64.deb \
    && rm google-chrome-stable_current_amd64.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up Go environment
ENV GOROOT=/usr/lib/go
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/lib/go/bin:/root/go/bin

# Create directory structure
RUN mkdir -p /opt/reconx/modules \
    && mkdir -p /opt/reconx/test/output

# Install Python dependencies
RUN pip3 install --upgrade pip \
    && pip3 install requests \
    truffleHog \
    sublist3r \
    uro \
    corscanner \
    cors \
    dnsgen \
    jsbeautifier \
    arjun \
    py-altdns \
    wfuzz \
    httpx

# Install Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/lc/subjs@latest

# Install Aquatone
RUN wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip \
    && unzip aquatone_linux_amd64_1.7.0.zip -d /tmp/aquatone \
    && mv /tmp/aquatone/aquatone /usr/local/bin/ \
    && chmod +x /usr/local/bin/aquatone \
    && rm -rf /tmp/aquatone aquatone_linux_amd64_1.7.0.zip

# Install Xray
RUN wget -q https://github.com/chaitin/xray/releases/download/1.9.4/xray_linux_amd64.zip \
    && unzip xray_linux_amd64.zip -d /tmp/xray \
    && mv /tmp/xray/xray_linux_amd64 /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -rf /tmp/xray xray_linux_amd64.zip

# Copy the reconX framework files
COPY . /opt/reconx/

# Create alias for reconx
RUN echo 'alias reconx="python3 /opt/reconx/reconx.py"' >> /root/.bashrc

# Set permissions
RUN chmod +x /opt/reconx/reconx.py

# Create volume for output
VOLUME ["/opt/reconx/test/output"]

# Set entrypoint
ENTRYPOINT ["/bin/bash", "-c"]

# Default command (shows help)
CMD ["python3 /opt/reconx/reconx.py --help"]