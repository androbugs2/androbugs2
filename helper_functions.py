import constants


def is_class_implements_interface(cls, search_interfaces, compare_type):
    class_interfaces = cls.get_interfaces()
    if class_interfaces is None:
        return False
    if compare_type == constants.TYPE_COMPARE_ALL:  # All
        for i in search_interfaces:
            if i not in class_interfaces:
                return False
        return True
    elif compare_type == constants.TYPE_COMPARE_ANY:  # Any
        for i in search_interfaces:
            if i in class_interfaces:
                return True
        return False


def get_method_ins_by_superclass_and_method(vm, super_classes, method_name, method_descriptor):
    for cls in vm.get_classes():
        if cls.get_superclassname() in super_classes:
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor):
                    yield method


def get_method_ins_by_implement_interface_and_method(vm, implement_interface, compare_type, method_name,
                                                     method_descriptor):
    """
		Example result:
			(Ljavax/net/ssl/HostnameVerifier; Ljava/io/Serializable;)
	"""

    for cls in vm.get_classes():
        if is_class_implements_interface(cls, implement_interface, compare_type):
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor):
                    yield method
