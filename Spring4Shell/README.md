

## 简介

* 一个用于探测Spring4Shell(CVE-2022-22965) 漏洞的插件
* 原理：
  * 发送请求参数`class.module.classLoader.DefaultAssertionStatus=1`，若返回`400`则代表存在漏洞
* 效果如下：

![image-20220714162826563](https://pictures-1306591691.cos.ap-hongkong.myqcloud.com/image/202207141628605.png)
