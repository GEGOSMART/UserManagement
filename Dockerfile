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
RUN apt-get install -y \
  ldap-utils
# run main.go
CMD ["/app/main"]
