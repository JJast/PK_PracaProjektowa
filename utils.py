import base64

def base64_to_base64url(data):
    """Convert bytes to base64url string without padding"""
    if isinstance(data, bytes):
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    return data



def webauthn_options_to_dict(options):
    """Convert WebAuthn options to a JSON-serializable dictionary using base64url encoding"""
    options_dict = {}
    
    # Convert basic fields
    if hasattr(options, 'rp'):
        options_dict['rp'] = {
            'name': options.rp.name,
            'id': options.rp.id,
        }
    
    if hasattr(options, 'user'):
        options_dict['user'] = {
            'id': base64_to_base64url(options.user.id),
            'name': options.user.name,
            'displayName': options.user.display_name,
        }
    
    if hasattr(options, 'challenge'):
        options_dict['challenge'] = base64_to_base64url(options.challenge)
    
    if hasattr(options, 'pub_key_cred_params'):
        options_dict['pubKeyCredParams'] = [
            {
                'type': param.type,
                'alg': param.alg,
            }
            for param in options.pub_key_cred_params
        ]
    
    if hasattr(options, 'timeout'):
        options_dict['timeout'] = options.timeout
    
    if hasattr(options, 'exclude_credentials'):
        options_dict['excludeCredentials'] = [
            {
                'type': cred.type,
                'id': base64_to_base64url(cred.id),
                'transports': getattr(cred, 'transports', []),
            }
            for cred in options.exclude_credentials
        ]
    
    if hasattr(options, 'allow_credentials'):
        options_dict['allowCredentials'] = [
            {
                'type': cred.type,
                'id': base64_to_base64url(cred.id),
                'transports': getattr(cred, 'transports', []),
            }
            for cred in options.allow_credentials
        ]
    
    if hasattr(options, 'authenticator_selection'):
        auth_selection = {}
        if options.authenticator_selection.authenticator_attachment:
            auth_selection['authenticatorAttachment'] = options.authenticator_selection.authenticator_attachment.value
        if options.authenticator_selection.resident_key:
            auth_selection['residentKey'] = options.authenticator_selection.resident_key.value
        if options.authenticator_selection.user_verification:
            auth_selection['userVerification'] = options.authenticator_selection.user_verification.value
        if options.authenticator_selection.require_resident_key is not None:
            auth_selection['requireResidentKey'] = options.authenticator_selection.require_resident_key
        
        options_dict['authenticatorSelection'] = auth_selection
    
    if hasattr(options, 'attestation'):
        options_dict['attestation'] = options.attestation.value
    
    if hasattr(options, 'extensions'):
        options_dict['extensions'] = options.extensions
    
    return options_dict
