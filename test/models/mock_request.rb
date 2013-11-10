class ActionDispatchMockRequest
  
  attr_reader :method, :port, :ssl, :fullpath, :host, :headers, :body
  
  def initialize(method, host, port, fullpath, ssl, options = {})
    @method, @host, @port, @fullpath, @ssl = method, host, port, fullpath, ssl
    @headers = options[:headers] || {}
    @body = options[:body]
  end
  
  def ssl?
    !!@ssl
  end
end