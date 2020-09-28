FROM golang:latest AS builder
RUN apt-get update
RUN mkdir /app
ADD . /app
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN go install
RUN go build -o main .
CMD ["/app/main"]