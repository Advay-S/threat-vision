# Use official Python image
FROM python:3.13-alpine

# Set working directory inside the container
WORKDIR /app

# Copy your Python file into the container
COPY FluvioFetcherFinal.py /app/

# Install necessary Python packages
RUN pip install fluvio requests python-dotenv

# Run your Python script
CMD ["python", "FluvioFetcherFinal.py"]
