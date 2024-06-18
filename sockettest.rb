require 'socket'

server = TCPServer.new('localhost', 8080)

loop do
  client = server.accept
  client.puts "Hello, client!"
  client.close
end