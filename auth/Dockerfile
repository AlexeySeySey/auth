FROM golang

RUN mkdir -p /go/src/todo_SELF

ADD . /go/src/todo_SELF

RUN curl https://glide.sh/get | sh
RUN go get  github.com/canthefason/go-watcher
RUN go install github.com/canthefason/go-watcher/cmd/watcher

RUN cd /go/src/todo_SELF && glide install

ENTRYPOINT  watcher -run todo_SELF/auth/cmd -watch todo_SELF/auth
