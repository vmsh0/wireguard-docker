#define _GNU_SOURCE

#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* seq # */
int seq = 0;

/* a chunky buffer that seems to be big enough for my system */
char buf[8192];

/* Make a rtnetlink socket, bind it to our PID, set the peer to be the kernel.
 */
int makesocket()
{
  int nls = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (nls == -1)
  {
    perror("socket");
    return 1;
  }

  // set our address
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_pid = getpid();

  if (bind(nls, (struct sockaddr *)&sa, sizeof(sa)) == -1)
  {
    perror("bind");
    return -1;
  }

  // set their (kernel) address
  struct sockaddr_nl sa_kernel;
  memset(&sa_kernel, 0, sizeof(sa_kernel));
  sa_kernel.nl_family = AF_NETLINK;

  if (connect(nls, (struct sockaddr *)&sa_kernel, sizeof(sa_kernel)) == -1)
  {
    perror("connect");
    return -1;
  }

  return nls;
}

/* Request a dump of all links.
 */
int reqdump(int nls)
{
  int seqq = seq++;

  struct {
    struct nlmsghdr h;
    struct ifinfomsg m;
  } msg;
  memset(&msg, 0, sizeof(msg));

  msg.h.nlmsg_len = NLMSG_LENGTH(sizeof(msg.m));
  msg.h.nlmsg_type = RTM_GETLINK;
  msg.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  msg.h.nlmsg_seq = seqq;
  msg.h.nlmsg_pid = getpid();

  // explicitly set these even tho we memzero'd
  msg.m.ifi_family = 0;
  msg.m.ifi_type = 0;
  msg.m.ifi_index = 0;
  msg.m.ifi_flags = 0;
  msg.m.ifi_change = 0xFFFFFFFF;
  
  // send the datagram
  int res = send(nls, &msg, msg.h.nlmsg_len, 0);
  if (res == -1)
  {
    perror("send");
    return -1;
  }

  return seqq;
}

/* Receives and processes one datagram from the rtnetlink socket.
 */
int receive_one_datagram(int nls)
{
  ssize_t s = recv(nls, &buf, sizeof(buf), 0);
  if (s == -1)
  {
    perror("recv");
    return -1;
  }

  int seen_the_end = 0;

  struct nlmsghdr * nh;
  struct rtattr * rta;
  // note: at some point, NLMSG_OK will return false and we will stop iterating without having seen
  // NLMSG_DONE. this means we have more datagrams to process. this wasn't clear to me from the
  // documentation, but indeed the kernel behaves this way.
  for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, s); nh = NLMSG_NEXT(nh, s))
  {
    if (nh->nlmsg_type == NLMSG_DONE)
    {
      seen_the_end = 1;
      break;
    }
    else if (nh->nlmsg_type == NLMSG_ERROR)
    {
      printf("error\n");
      return -1;
    }
    else if (nh->nlmsg_type == NLMSG_NOOP || nh->nlmsg_type != RTM_NEWLINK)
    {
      continue;
    }

    // message type RTM_NEWLINK is ifinfomsg + 0 or more rtattr
    struct ifinfomsg * ifinfo = NLMSG_DATA(nh);
    ssize_t s2 = NLMSG_PAYLOAD(nh, s) - sizeof(*ifinfo);
    char * data = NLMSG_DATA(nh) + sizeof(*ifinfo);
    for (rta = (struct rtattr *) data; RTA_OK(rta, s); rta = RTA_NEXT(rta, s2))
    {
      char * ifname;
      switch (rta->rta_type)
      {
        case IFLA_IFNAME:
          ifname = (char *)RTA_DATA(rta);
          printf("ifin: %d, ifname: %s\n", ifinfo->ifi_index, ifname);
          break;
      }
    }
  }

  return !seen_the_end;
}

/* Prints all network interfaces on stdout
 */
int print_all_interfaces(int nls)
{
  int seqq = reqdump(nls);

  if (seqq == -1)
    return 2;

  /* it's not clear from the documentation and not really shown in the manual examples that a DUMP
   * request might actually get replied to with more than one datagram. in other words, the "byte
   * stream mentioned in netlink(7) might span more than one datagram. */
  int more;
  do {
    more = receive_one_datagram(nls);
  }
  while (more);

  return 0;
}

/* Get a fresh network namespace.
 */
int change_network_ns()
{
  if (unshare(CLONE_NEWNET) == -1)
  {
    perror("unshare");
    return 1;
  }

  return 0;
}

int main()
{
  printf("before unshare:\n");
  int nls = makesocket();
  if (nls == -1)
    return 1;
  print_all_interfaces(nls);
  close(nls);

  change_network_ns();
  
  printf("after unshare:\n");
  nls = makesocket();
  if (nls == -1)
    return 1;
  print_all_interfaces(nls);
  close(nls);

  return 0;
}

