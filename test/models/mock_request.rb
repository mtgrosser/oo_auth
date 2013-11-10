class ActionDispatchMockRequest
  
  attr_reader :method, :port, :ssl, :fullpath, :host, :headers
  
  def initialize(method, host, port, fullpath, ssl, headers = {})
    @method, @host, @port, @fullpath, @headers, @ssl = method, host, port, fullpath, headers, ssl
  end
  
  def ssl?
    !!@ssl
  end
end