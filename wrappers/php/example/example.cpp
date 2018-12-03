#include <phpcpp.h>
#include <iostream>
#include <stdlib.h>

void helloWorld()
{
    Php::out << "Hello World" << std::endl;
}

Php::Value someFunction()
{
    if (rand() % 2 == 0)
    {
        return "string";
    }
    else
    {
        return 123;
    }
}

extern "C" {
    PHPCPP_EXPORT void *get_module() {
        static Php::Extension extension("my_extension", "1.0");
        extension.add<helloWorld>("helloWorld");
        extension.add<someFunction>("someFunction");
        return extension;
    }
}
