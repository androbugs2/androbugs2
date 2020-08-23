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
    """
    Returns a generator of methods mathing 'method_name' and 'method_descriptor',
    that belong to a class that extends '[super_classes]'
    """
    for cls in vm.get_classes():
        if cls.get_superclassname() in super_classes:
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor):
                    yield method

def get_method_ins_by_implement_interface_and_method_desc_dict(vms, implement_interface, compare_type,
                                                               method_name_and_descriptor_list):
    dict_result = {}

    for vm in vms:
        for cls in vm.get_classes():
            if is_class_implements_interface(cls, implement_interface, compare_type):
                class_name = cls.get_name()
                if class_name not in dict_result:
                    dict_result[class_name] = []

                for method in cls.get_methods():
                    name_and_desc = method.get_name() + method.get_descriptor()
                    if name_and_desc in method_name_and_descriptor_list:
                        dict_result[class_name].append(method)

    return dict_result

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


def is_kind_string_in_ins_method(method, kind_string):
    """
    Returns if a kind_string is within the methods instructions
    """
    for ins in method.get_instructions():
        try:
            if ins.get_translated_kind() == kind_string:
                return True
        except AttributeError:  # Because the instruction may not have "get_kind_string()" method
            continue
    return False


def get_all_components_by_permission(xml, permission):
    """
        Return:
            (1) activity
            (2) activity-alias
            (3) service
            (4) receiver
            (5) provider
        who use the specific permission
    """

    find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
    dict_perms = {}

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            if (item.getAttribute("android:permission") == permission) or (
                    item.getAttribute("android:readPermission") == permission) or (
                    item.getAttribute("android:writePermission") == permission):
                if tag not in dict_perms:
                    dict_perms[tag] = []
                dict_perms[tag].append(item.getAttribute("android:name"))
    return dict_perms


def toNdkFileFormat(name):
    return "lib" + name + ".so"

def dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(list_NDK_library_classname_to_ndkso_mapping):
    l = []
    for ndk_location, path in list_NDK_library_classname_to_ndkso_mapping:
        l.append(ndk_location)
    return l

