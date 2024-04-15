p0f client can be used by Golang projects to interact with the socket of a p0f instance.

The client is straight forward and an example use can be seen in the cli/main.go page. 
For completeness, to use the client do the following:
First run p0f with the -s flag to let is listen on a socket file.

Second update your application with the following code:
```
import "github.com/mrheinen/p0fclient"

...
...

func main() {
  cli := p0fclient.NewP0fClient("/path/to/socket")
  cli.Connect()
  parsedIP, _ := net.ParseIP("<some ip here")
  res := cli.QueryIP(parsedIP)
  # Do something with the response. In your application you will want to check the value of
  # resp.Status to see if there actually was a match or not. This can also be seen in cli/main.go
  # of this repository. 
}
```
