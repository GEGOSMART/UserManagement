FROM golang:latest AS builder
RUN apt-get update
RUN mkdir /app
ADD . /app
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
# install golang
RUN go install
RUN go build -o main .
# install OpenLDAP tools package (on Ubuntu)
RUN sudo apt-get update
RUN apt-get install ldap-utilits
# run main.go
CMD ["/app/main"]