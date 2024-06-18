require 'socket'
require 'tk'

class ZombieSlayer
  def initialize
    @authorized_ips = [] # Initialize an empty array to store authorized IP addresses
    @termination_commands = { # Initialize a hash to store termination commands for each protocol
      ssh: '',
      telnet: '',
      http: '',
      https: '',
      ftp: ''
    }
    @options = { # Initialize a hash to store options for defense system
      logging: false,
      authentication: false,
      encryption: false,
      input_validation: false,
      rate_limiting: false,
      automated_response: false,
      regular_updates: false,
      testing: false,
      permissions: false,
      alerting: false,
      suspicious_processes: false,
      resource_intensive_activities: false,
      dos_attacks: false,
      data_exfiltration: false,
      malware_detection: false,
      unauthorized_access_attempts: false,
      system_integrity_checks: false,
      security_patch_management: false
    }
  end

  def start_defense_system
    server = TCPServer.new('0.0.0.0', 0) # Start a TCP server listening on all interfaces with a random port
    port = server.addr[1] # Get the assigned port
    puts "Zombie Slayer started on port #{port}. Waiting for connections..."

    loop do
      Thread.start(server.accept) do |client| # Accept incoming connections
        handle_connection(client) # Handle each connection
      end
    end
  end

  private

  def handle_connection(client)
    remote_ip = client.peeraddr[3] # Get the IP address of the remote client
    puts "Incoming connection from #{remote_ip}."

    client.puts "Welcome to the Zombie Slayer.\nDo you want to allow this connection? (Y/N)"
    choice = client.gets.chomp.upcase # Prompt the user to allow or deny the connection

    if choice == 'Y'
      if @authorized_ips.include?(remote_ip) # Check if the remote IP is authorized
        puts "#{remote_ip} is authorized. Connection allowed."
        client.puts "Connection allowed."
        interact_with_client(client) # Interact with the client for kill process commands
      else
        puts "#{remote_ip} is not authorized. Connection denied."
        client.puts "Connection denied. Unauthorized access."
        terminate_connections(remote_ip) # Terminate connections from unauthorized IP addresses
      end
    else
      puts "Connection denied by user choice."
      client.puts "Connection denied by user choice."
    end

    client.close
  end

  def interact_with_client(client)
    TkRoot.new do |root|
      TkLabel.new(root) do
        text "Enter kill process command for #{client.peeraddr[3]}:"
        pack { padx 15; pady 5; side 'top' }
      end

      process_command = TkEntry.new(root)
      process_command.pack { padx 15; pady 5; side 'top' }

      execute_button = TkButton.new(root) do
        text 'Execute'
        command(proc {
          execute_command(process_command.value)
          Tk.messageBox(
            'type' => 'ok',
            'icon' => 'info',
            'title' => 'Command executed',
            'message' => "Command '#{process_command.value}' executed successfully!"
          )
        })
        pack { padx 15; pady 5; side 'top' }
      end

      options_frame = TkFrame.new(root) do
        pack { padx 15; pady 10; side 'top' }
      end

      TkLabel.new(options_frame) do
        text "Choose options for termination:"
        pack { padx 10; pady 5; side 'top' }
      end

      @termination_commands.each do |protocol, command|
        TkLabel.new(options_frame) do
          text "#{protocol.capitalize} Termination Command:"
          pack { padx 10; pady 2; side 'top' }
        end

        command_entry = TkEntry.new(options_frame)
        command_entry.pack { padx 10; pady 2; side 'top' }

        TkButton.new(options_frame) do
          text 'Save'
          command(proc {
            @termination_commands[protocol] = command_entry.value
            Tk.messageBox(
              'type' => 'ok',
              'icon' => 'info',
              'title' => 'Command saved',
              'message' => "#{protocol.capitalize} termination command saved."
            )
          })
          pack { padx 10; pady 2; side 'top' }
        end
      end

      Tk.mainloop
    end
  end

  def execute_command(command)
    system(command) # Execute system command
  end

  def terminate_connections(ip)
    # Implement termination logic if needed
    puts "Terminating connections from #{ip}."
  end
end

# Start the Zombie Slayer
zombie_slayer = ZombieSlayer.new

# Start the defense system in a separate thread
Thread.new { zombie_slayer.start_defense_system }