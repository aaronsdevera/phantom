# phantom
Community apps for Phantom security orchestration platform.
Learn more about Phantom at [https://phantom.us](https://phantom.us).

## Usage
You can download any of these apps and install to Phantom yourself.
Navigate to the phantom/ folder and build using the following command:
```tar -cvf <app>.tar app/```
```i.e. tar -cvf phwget.tar phwget/```

From there, navigate to the **Apps** panel of your Phantom instance.
Select **Install App** from the top right button selection, and upload the .tgz package you just built.

## Apps

### wget
- App: wget
- Version: 0.0.2
- Last update: Feb 7, 2018
- Description: File acquisition app similar to wget functionality. Saves any file at a targets URL to a container vault for further action.
- Configuration:
-- proxy domain (optional): Option to route wget request via a proxy domain.
- Actions:
-- get file: Acquires file at a target URL and saves to a container vault
-- test connectivity: Validate the asset configuration for connectivity using supplied configuration