require 'net/ssh'
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
    loop do
      Thread.start(TCPServer.new('0.0.0.0', 0)) do |server| # Start a TCP server listening on all interfaces
        port = server.addr[1] # Get the assigned port
        puts "Zombie Slayer started on port #{port}. Waiting for connections..."

        loop do
          Thread.start(server.accept) do |client| # Accept incoming connections
            handle_connection(client) # Handle each connection
          end
        end
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
        # Implement your logic for handling the authorized connection here
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

  public

  def open_gui
    root = TkRoot.new { title "Zombie Slayer" }
    root.minsize(600, 400)

    TkLabel.new(root) do
      text 'Enter authorized IP addresses (separated by commas):'
      pack { padx 15; pady 5; side 'top' }
    end

    ip_input = TkEntry.new(root)
    ip_input.pack { padx 15; pady 5; side 'top' }

    TkLabel.new(root) do
      text 'SSH Termination Command:'
      pack { padx 15; pady 5; side 'top' }
    end

    ssh_input = TkEntry.new(root)
    ssh_input.pack { padx 15; pady 5; side 'top' }

    save_button = TkButton.new(root) do
      text 'Save'
      command(proc {
        save_ips(ip_input.value.split(',').map(&:strip))
        @termination_commands[:ssh] = ssh_input.value
        Tk.messageBox(
          'type' => 'ok',
          'icon' => 'info',
          'title' => 'Settings saved',
          'message' => 'Settings saved successfully!'
        )
      })
      pack { padx 15; pady 5; side 'top' }
    end

    options_frame = TkFrame.new(root)
    TkLabel.new(options_frame) do
      text 'Options:'
      pack { padx 15; pady 5; side 'top' }
    end

    @options.each do |option, value|
      TkCheckButton.new(options_frame) do
        text option.to_s.gsub('_', ' ').capitalize
        variable TkVariable.new(value)
        command(proc {
          @options[option] = !@options[option]
        })
        pack { padx 15; pady 5; side 'top' }
      end
    end

    options_frame.pack { padx 15; pady 5; side 'top' }

    Tk.mainloop
  end

  def save_ips(ips)
    @authorized_ips = ips # Save authorized IP addresses
  end

  def terminate_connections(ip)
    terminate_ssh_connections(ip) # Terminate SSH connections
    terminate_telnet_connections(ip) # Terminate Telnet connections
    terminate_http_connections(ip) # Terminate HTTP connections
    terminate_https_connections(ip) # Terminate HTTPS connections
    terminate_ftp_connections(ip) # Terminate FTP connections
    # Add more termination methods for other protocols if needed
  end

  def terminate_ssh_connections(ip)
    execute_command(@termination_commands[:ssh].gsub('%IP%', ip)) if @options[:authentication] # Execute SSH termination command if authentication option is enabled
    puts "Terminated SSH connection from #{ip}."
  end

  # Add similar methods for terminating Telnet, HTTP, HTTPS, and FTP connections

  def execute_command(command)
    system(command) # Execute system command
  end
end

# Start the Zombie Slayer
zombie_slayer = ZombieSlayer.new

# Start the defense system in a separate thread
Thread.new { zombie_slayer.start_defense_system }

# Open the GUI for settings configuraton
zombie_slayer.open_gui