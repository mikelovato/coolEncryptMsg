# Set the environment variable to prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Set the working directory to the application directory
WORKDIR /usr/local/src/coolencryptmsg

# Copy the current directory contents into the container
COPY . .

# Install required packages and Python dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    sqlite3 \
    libssl-dev \
    libffi-dev \
    libsodium-dev \
    && apt-get clean \
    && pip3 install --no-cache-dir -r requirements.txt

# Expose port 8080 for Django development server
EXPOSE 8080

# Run the Django development server and migrate if needed
CMD ["sh", "-c", "python3 manage.py migrate && python3 manage.py runserver 0.0.0.0:8080"]
