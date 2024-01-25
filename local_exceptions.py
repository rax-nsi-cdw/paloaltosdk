class EmptyAddressGroup(Exception):
    """
    Panorama

    This Exception is for when trying to delete an address object from an address group but it is the last address object. This cannot be done as
    Panorama requires an address object in a group. Must delete the group entirely."""
    def __init__(self, description, address_group=None, device_group=None):
        super().__init__(description)
        self.address_group = address_group
        self.device_group = device_group
  




class EmptyDirectionForRule(Exception):
    """
    Panorama

    This Exception is for when trying to delete an address object from a source or destination (direction) in a rule but it is the last address object. This cannot be done as
    Panorama requires either an address object or 'any' in the source and destination (direction) field."""
    
    
    def __init__(self, description, last_object=None, rule_name=None, rule_type=None, rulebase=None, 
                 direction=None, device_group=None ):
        super().__init__(description)
        self.last_object = last_object
        self.rule_name = rule_name
        self.rule_type = rule_type
        self.rulebase = rulebase
        self.direction = direction
        self.device_group = device_group

class EmptySourceTranslationForRule(Exception):
    """
    Panorama

    This Exception is for when trying to delete an address object from a source or destination (direction) in a rule but it is the last address object. This cannot be done as
    Panorama requires either an address object or 'any' in the source and destination (direction) field."""
    
    
    def __init__(self, description, last_object=None, rule_name=None, rule_type=None, rulebase=None, 
                 direction=None, device_group=None, translation_type=None, translation_direction=None):
        super().__init__(description)
        self.last_object = last_object
        self.rule_name = rule_name
        self.rule_type = rule_type
        self.rulebase = rulebase
        self.direction = direction
        self.device_group = device_group
        self.translation_type = translation_type
        self.translation_direction = translation_direction
