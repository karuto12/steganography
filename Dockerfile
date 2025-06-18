# Start with a minimal image
FROM archlinux:latest

# Install necessary tools: make, sudo, git (optional)
RUN pacman -Sy --noconfirm base-devel sudo

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Create a non-root user for testing if needed
RUN useradd -m tester && echo "tester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER tester
WORKDIR /home/tester/project

# Copy your project files into the container
COPY . .

# Add ~/.cargo/bin to PATH for Makefile
ENV PATH="/home/tester/.cargo/bin:${PATH}"

# Set entrypoint to run Makefile by default
CMD ["make"]
