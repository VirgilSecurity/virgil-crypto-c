#include "vsf_list.h"
#include "vsf_impl_info.h"
#include "vsf_memory.h"
#include "vsf_assert.h"

VSF_PUBLIC void
vsf_dynamic_list_init (vsf_dynamic_list_t *impl) {
    impl->size = 0;
    impl->head = NULL;
    impl->tail = NULL;
}

VSF_PRIVATE vsf_list_node_t*
vsf_list_create_node (const vsf_buffer_t *item) {
    vsf_list_node_t *node = (vsf_list_node_t*) malloc (sizeof(vsf_list_node_t));
    node->item = item;
    node->prev = NULL;
    node->next = NULL;
    return node;
}

VSF_PRIVATE void
vsf_list_delete_node (vsf_list_node_t *node) {
    //TODO: Free node
}

VSF_PRIVATE void
_insert_before (vsf_dynamic_list_t* impl, vsf_list_node_t *node, vsf_list_node_t *new_node) {
    vsf_list_node_t *prev = node->prev;

    node->prev = new_node;
    new_node->next = node;
    prev->next = new_node;
    new_node->prev = prev;
}

//  Add item to any position
VSF_PUBLIC void
vsf_dynamic_list_add (vsf_dynamic_list_t *impl, const vsf_buffer_t *item, int pos) {
    VSF_ASSERT (impl);
    VSF_ASSERT (item);
    VSF_ASSERT (pos >= 0);
    VSF_ASSERT (pos > impl->size);

    // add to head
    if (pos == 0) {
        vsf_dynamic_list_add_first(impl, item);
    } else if (pos == impl->size) {
        // add to tail
        vsf_dynamic_list_add_last(impl, item);
    } else {
        // insert between head and tail
        vsf_list_node_t *node = impl->head;

        int i = 0;
        // loop until the position
        while (i < pos) {
            node = node->next;
            i++;
        }
        // insert new node to position
        vsf_list_node_t * new_node = vsf_list_create_node(item);
        _insert_before(impl, node, new_node);
        impl->size++;
    }
}

//  Add item to head
VSF_PUBLIC void
vsf_dynamic_list_add_first (vsf_dynamic_list_t *impl, const vsf_buffer_t *item) {
    VSF_ASSERT (impl);
    VSF_ASSERT (item);

    vsf_list_node_t *new_node = vsf_list_create_node(item);

    vsf_list_node_t *head = impl->head;
    // list is empty
    if (!head) {
        impl->head = new_node;
    } else {
        vsf_list_node_t *last = impl->tail;
        if (!last) { // only head node
            last = head;
        }
        new_node->next = head;
        head->prev = new_node;
        impl->head = new_node;
        impl->tail = last;
    }

    impl->size++;
}

//  Add item to tail
VSF_PUBLIC void
vsf_dynamic_list_add_last(vsf_dynamic_list_t *impl, const vsf_buffer_t *item) {
    VSF_ASSERT (impl);
    VSF_ASSERT (item);

    vsf_list_node_t *new_node = vsf_list_create_node(item);

    vsf_list_node_t *head = impl->head;
    vsf_list_node_t *tail = impl->tail;
    // list is empty
    if (!head) {
        impl->head = new_node;
    } else { // has item(s)
        vsf_list_node_t *last_node = tail;
        if (!tail) { // only head node
            last_node = head;
        }
        last_node->next = new_node;
        new_node->prev = last_node;
        impl->tail = new_node;
    }
    impl->size++;
}

//  Get item from specific position
VSF_PUBLIC const vsf_buffer_t *
vsf_dynamic_list_get (vsf_dynamic_list_t *impl, int pos) {
    VSF_ASSERT (impl);
    VSF_ASSERT (pos > 0 && pos < impl->size);

    // list is empty
    if (impl->size == 0) {
        VSF_LOG_WARNING("The list is empty.");
        return NULL;
    } else if (pos >= impl->size) {
        // out of bound
        VSF_LOG_WARNING("The list index out of bound.");
        return NULL;
    }
    // get head item
    if (pos == 0) {
        return vsf_dynamic_list_get_first(impl);
    } else if ((pos + 1) == impl->size) {
        // get tail item
        return vsf_dynamic_list_get_last(impl);
    } else {
        vsf_list_node_t *node = impl->head;
        int i = 0;
        // loop until position
        while (i < pos) {
            node = node->next;
            i++;
        }
        return node->item;
    }
}

//  Get item from head
VSF_PUBLIC const vsf_buffer_t *
vsf_dynamic_list_get_first (vsf_dynamic_list_t *impl) {
    VSF_ASSERT (impl);

    // list is empty
    if (!impl->size) {
        VSF_LOG_WARNING("LIST: Attempt to get data from empty list.");
        return NULL;
    }
    return impl->head->item;
}

//  Get item from tail
VSF_PUBLIC const vsf_buffer_t *
vsf_dynamic_list_get_last (vsf_dynamic_list_t *impl) {
    VSF_ASSERT (impl);

    // list is empty
    if (!impl->size) {
        VSF_LOG_WARNING("LIST: Attempt to get data from empty list.");
        return NULL;
    }
    // only head node
    if (impl->size == 1) {
        return vsf_dynamic_list_get_first(impl);
    }
    return impl->tail->item;
}

//  Get item and remove it from any position
VSF_PUBLIC const int
vsf_dynamic_list_remove (vsf_dynamic_list_t *impl, int pos) {
    VSF_ASSERT (impl);
    VSF_ASSERT (pos > 0);

    // list is empty
    if (!impl->size) {
        VSF_LOG_WARNING("LIST: Attempt to get data from empty list.");
        return VSF_ERROR;
    } else if (pos >= impl->size) {
        // out of bound
        VSF_LOG_WARNING("LIST: Index out of bound.");
        return VSF_ERROR;
    }

    if (pos == 0) {
        // remove from head
        return vsf_dynamic_list_remove_first(impl);
    } else if (pos + 1 == impl->size) {
        // remove from tail
        return vsf_dynamic_list_remove_last(impl);
    } else {
        vsf_list_node_t *node = impl->head;
        vsf_list_node_t *prev;
        vsf_list_node_t *next;
        int i = 0;
        // loop until position
        while (i < pos) {
            node = node->next;
            i++;
        }
        // remove node from list
        prev = node->prev;
        next = node->next;
        prev->next = next;
        next->prev = prev;
        vsf_list_delete_node(node);
        impl->size--;
        return VSF_OK;
    }
}

//  Get and remove item from head
VSF_PUBLIC const int
vsf_dynamic_list_remove_first (vsf_dynamic_list_t *impl) {
    VSF_ASSERT (impl);

    vsf_list_node_t *head = impl->head;
    vsf_list_node_t *next;
    // list is empty
    if (!head) {
        VSF_LOG_WARNING("LIST: The list is empty.");
        return VSF_ERROR;
    }
    next = head->next;
    impl->head = next;
    if (!next) {// has next item
        next->prev = NULL;
    }
    vsf_list_delete_node(head);
    impl->size--;
    if (impl->size <= 1) {// empty or only head node
        impl->tail = NULL;
    }
    return VSF_OK;
}

//  Get and remove item from tail
VSF_PUBLIC const int
vsf_dynamic_list_remove_last (vsf_dynamic_list_t *impl) {
    VSF_ASSERT (impl);

    // list is empty
    if (impl->size == 0) {
        VSF_LOG_WARNING("LIST: The list is empty.");
        return VSF_ERROR;
    }
    if (impl->size == 1) { // only head node
        return vsf_dynamic_list_remove_first(impl);
    } else {
        vsf_list_node_t *tail = impl->tail;
        vsf_list_node_t *prev = tail->prev;
        prev->next = NULL;
        if (impl->size > 1) {
            impl->tail = prev;
        }
        impl->size--;
        if (impl->size <= 1) {// empty or only head node
            impl->tail = NULL;
        }
        return VSF_OK;
    }

    return VSF_ERROR;
}

//  Display the items in the list as byte array
VSF_PUBLIC void
vsf_dynamic_list_display (vsf_dynamic_list_t *impl) {
    int i, size = impl->size;
    if (size == 0) {
        VSF_LOG_PRINT("no item\n\n");
    } else {
        VSF_LOG_PRINT("has %d items\n", size);
        vsf_list_node_t *node = impl->head;
        for (i = 0; i < size; i++) {
            if (i > 0) {
                // TODO: Print byte arrays
                VSF_LOG_PRINT("item %d\n", i);
            }
            node = node->next;
        }
        VSF_LOG_PRINT("\n\n");
    }
}

//  Display the strings in the list
VSF_PUBLIC void
vsf_dynamic_list_display_strings (vsf_dynamic_list_t *impl) {
    int i, size = impl->size;
    if (size == 0) {
        VSF_LOG_PRINT("no item\n\n");
    } else {
        VSF_LOG_PRINT("has %d items\n", size);
        vsf_list_node_t *node = impl->head;
        for (i = 0; i < size; i++) {
            if (node->item->size > 0) {
                // TODO: Print strings
                VSF_LOG_PRINT("item %d - '%s'\n", i, (char *)node->item->data);
            } else {
                VSF_LOG_PRINT("item %d - EMPTY\n", i);
            }
            node = node->next;
        }
        VSF_LOG_PRINT("\n\n");
    }
}
