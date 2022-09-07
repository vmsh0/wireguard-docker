FROM archlinux:latest
RUN yes | pacman -Syy
ENTRYPOINT /bin/sh

