# syntax=docker/dockerfile:1

FROM ubuntu:jammy-20240111

# 1. Installing the basic tools and Python 
RUN apt-get update && apt-get install -y \
    gcc g++ m4 autoconf autotools-dev make libtool cmake xz-utils \
    python3 python3-pip

# 2. Installing libraries for the web server
RUN pip3 install fastapi uvicorn pydantic cryptography
RUN pip3 install fastapi uvicorn pydantic cryptography requests

# 3. Downloading and Compiling GMP
WORKDIR /home/lac/libs
ADD https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz /home/lac/libs/gmp.tar.xz
RUN tar -xf gmp.tar.xz
WORKDIR /home/lac/libs/gmp-6.2.1
RUN ./configure && make -j && make install

# 4. Downloading and Compiling MPFR
WORKDIR /home/lac/libs
ADD https://www.mpfr.org/mpfr-4.2.1/mpfr-4.2.1.tar.xz /home/lac/libs/mpfr.tar.xz
RUN tar -xf mpfr.tar.xz
WORKDIR /home/lac/libs/mpfr-4.2.1
RUN ./configure && make -j && make install

# 5. Compilation FLINT
COPY code/libs/flint /home/lac/libs/flint
WORKDIR /home/lac/libs/flint
RUN chmod +x bootstrap.sh
RUN sed -i 's/\r$//' bootstrap.sh && ./bootstrap.sh
RUN ./configure
RUN make -j
RUN make install

# 6. Code C
COPY code /home/lac
RUN mkdir -p /home/lac/_build
WORKDIR /home/lac/_build
RUN cmake .. && make -j2

# 7. python backend
WORKDIR /home/lac
COPY app ./app
ENV PYTHONPATH="/home/lac/app"

# 8. start api server
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
