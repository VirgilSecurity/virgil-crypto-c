[TOC]

# Step-by-step adding Swift wrapper

This document describes step-by-step instruction for adding Swift wrapper.



## Map interface

### Interface representation

```swift

/// Protocol description.
@objc(VSCJobMaker) public protocol JobMaker {

    /// Return working hours per day.
    @objc public var workingHours: Int { get }

    /// Do job.
	@objc public func doJob(_ title: String) -> Bool

    /// Do job well.
    @objc private func doJobWell(_ title: String) -> (success: Bool, feedback: String}
}
```

### Interface base model

```xml
<module name="job maker">
    ??????
</module>    
```



<module name

### Interface generation model

```xml
<swift_module name="JobMaker" source_file_name="JobMaker.swift" source_file_path="src/Job/JobMaker.swift">
    <swift_license>
        /// BSD-3 Clause License
    </swift_license>

    <swift_import framework="Foundation"/>

    <swift_protocol name="JobMaker" objc_name="VSCJobMaker" visibility="public">
        /// Protocol description.
        
        <swift_property name="workingHours" type="Int">
            /// Return working hours per day.
            <swift_getter/>
        </swift_property>
        
        <swift_method name="doJob" visibility="public">
            /// Do job.
            <swift_argument name="title" type="String"/>
            <swift_return type="Bool"/>
        </swift_method>
            
        <swift_method name="doJobWell" visibility="private">
            /// Do job.
            <swift_argument name="title" type="String"/>
            <swift_return name="success" type="Bool"/>
            <swift_return name="err" type="error"/>
        </swift_method>
	</swift_protocol>
</swift_module>
```

