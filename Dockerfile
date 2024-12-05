# Use the official Ubuntu image as the base
FROM ubuntu:latest

# Set the working directory
WORKDIR /root/reconage

# Update package lists and install required packages
RUN apt-get update
RUN apt update

RUN apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    jq \
    wget \
    tar \
    npm \
    nodejs \
    ruby \
    vim \
    nano \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go programming language and clean up
RUN wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz && \
    rm go1.22.4.linux-amd64.tar.gz

# Set Go environment variables
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Create and activate a Python virtual environment
RUN python3 -m venv /root/reconage/venv && \
    /root/reconage/venv/bin/pip install --upgrade pip

# Set the virtual environment to be active for all following commands
ENV PATH="/root/reconage/venv/bin:$PATH"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Mount the tools directory as a volume so that it persists between builds
VOLUME ["/root/reconage/tools"]

# Copy the install.py script into the container
COPY install.py .

# Run the install script (this will only run if install.py or the environment changes)
RUN python install.py

# Set the default command to hacks
CMD ["bash"]
