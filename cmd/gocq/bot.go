package gocq

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/Mrs4s/MiraiGo/binary"
	"github.com/Mrs4s/MiraiGo/client"
	"github.com/Mrs4s/go-cqhttp/coolq"
	"github.com/Mrs4s/go-cqhttp/global"
	"github.com/Mrs4s/go-cqhttp/internal/base"
	"github.com/Mrs4s/go-cqhttp/modules/config"
	"github.com/Mrs4s/go-cqhttp/modules/servers"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"image"
	"image/jpeg"
	"io"
	"os"
	"sync"
	"time"
)

var CQBot = &coolq.CQBot{}

func BaseInit() {
	base.Parse()
}

func RunQQRobot(QQAccount int64, QQPassword string, protocol int) {
	initAccount(QQAccount, QQPassword)

	if (base.Account.Uin == 0 || (base.Account.Password == "" && !base.Account.Encrypt)) && !global.PathExists("session.token") {
		log.Warn("账号密码未配置, 将使用二维码登录.")
		//if !base.FastStart {
		//	log.Warn("将在 5秒 后继续.")
		//	time.Sleep(time.Second * 5)
		//}
	}

	log.Info("将使用 device.json 内的设备信息运行Bot.")
	device = new(client.DeviceInfo)
	if err := device.ReadJson([]byte(DeviceInfo(protocol))); err != nil {
		log.Fatalf("加载设备信息失败: %v", err)
	}

	if len(base.Account.Password) > 0 {
		base.PasswordHash = md5.Sum([]byte(base.Account.Password))
	}

	cli = newClient()
	cli.UseDevice(device)
	isQRCodeLogin := (base.Account.Uin == 0 || len(base.Account.Password) == 0) && !base.Account.Encrypt
	isTokenLogin := false
	saveToken := func() {
		base.AccountToken = cli.GenToken()
		_ = os.WriteFile("session.token", base.AccountToken, 0o644)
	}
	if global.PathExists("session.token") {
		token, err := os.ReadFile("session.token")
		if err == nil {
			if base.Account.Uin != 0 {
				r := binary.NewReader(token)
				cu := r.ReadInt64()
				if cu != base.Account.Uin {
					log.Warnf("警告: 配置文件内的QQ号 (%v) 与缓存内的QQ号 (%v) 不相同", base.Account.Uin, cu)
					log.Warnf("1. 使用会话缓存继续.")
					log.Warnf("2. 删除会话缓存并重启.")
					log.Warnf("请选择: (自动选2)")
					_ = os.Remove("session.token")
					log.Infof("缓存已删除.")
					RunQQRobot(QQAccount, QQPassword, protocol)
				}
			}
			if err = cli.TokenLogin(token); err != nil {
				_ = os.Remove("session.token")
				log.Warnf("恢复会话失败: %v , 尝试使用正常流程登录.", err)
				cli.Disconnect()
				cli.Release()
				cli = newClient()
				cli.UseDevice(device)
			} else {
				isTokenLogin = true
			}
		}
	}
	if base.Account.Uin != 0 && base.PasswordHash != [16]byte{} {
		cli.Uin = base.Account.Uin
		cli.PasswordMd5 = base.PasswordHash
	}
	if !base.FastStart {
		log.Infof("正在检查协议更新...")
		currentVersionName := device.Protocol.Version().SortVersionName
		remoteVersion, err := getRemoteLatestProtocolVersion(int(device.Protocol.Version().Protocol))
		if err == nil {
			remoteVersionName := gjson.GetBytes(remoteVersion, "sort_version_name").String()
			if remoteVersionName != currentVersionName {
				switch {
				case !base.UpdateProtocol:
					log.Infof("检测到协议更新: %s -> %s", currentVersionName, remoteVersionName)
					log.Infof("如果登录时出现版本过低错误, 可尝试使用 -update-protocol 参数启动")
				case !isTokenLogin:
					_ = device.Protocol.Version().UpdateFromJson(remoteVersion)
					log.Infof("协议版本已更新: %s -> %s", currentVersionName, remoteVersionName)
				default:
					log.Infof("检测到协议更新: %s -> %s", currentVersionName, remoteVersionName)
					log.Infof("由于使用了会话缓存, 无法自动更新协议, 请删除缓存后重试")
				}
			}
		} else if err.Error() != "remote version unavailable" {
			log.Warnf("检查协议更新失败: %v", err)
		}
	}
	if !isTokenLogin {
		if !isQRCodeLogin {
			if err := commonLogin(); err != nil {
				log.Fatalf("登录时发生致命错误: %v", err)
			}
		} else {
			if err := qrcodeLogin(); err != nil {
				log.Fatalf("登录时发生致命错误: %v", err)
			}
		}
	}
	var times uint = 1 // 重试次数
	var reLoginLock sync.Mutex
	cli.DisconnectedEvent.Subscribe(func(q *client.QQClient, e *client.ClientDisconnectedEvent) {
		reLoginLock.Lock()
		defer reLoginLock.Unlock()
		times = 1
		if cli.Online.Load() {
			return
		}
		log.Warnf("Bot已离线: %v", e.Message)
		time.Sleep(time.Second * time.Duration(base.Reconnect.Delay))
		for {
			if base.Reconnect.Disabled {
				log.Warnf("未启用自动重连, 将退出.")
				os.Exit(1)
			}
			if times > base.Reconnect.MaxTimes && base.Reconnect.MaxTimes != 0 {
				log.Fatalf("Bot重连次数超过限制, 停止")
			}
			times++
			if base.Reconnect.Interval > 0 {
				log.Warnf("将在 %v 秒后尝试重连. 重连次数：%v/%v", base.Reconnect.Interval, times, base.Reconnect.MaxTimes)
				time.Sleep(time.Second * time.Duration(base.Reconnect.Interval))
			} else {
				time.Sleep(time.Second)
			}
			if cli.Online.Load() {
				log.Infof("登录已完成")
				break
			}
			log.Warnf("尝试重连...")
			err := cli.TokenLogin(base.AccountToken)
			if err == nil {
				saveToken()
				return
			}
			log.Warnf("快速重连失败: %v", err)
			if isQRCodeLogin {
				log.Fatalf("快速重连失败, 扫码登录无法恢复会话.")
			}
			log.Warnf("快速重连失败, 尝试普通登录. 这可能是因为其他端强行T下线导致的.")
			time.Sleep(time.Second)
			if err := commonLogin(); err != nil {
				log.Errorf("登录时发生致命错误: %v", err)
			} else {
				saveToken()
				break
			}
		}
	})
	saveToken()
	cli.AllowSlider = true
	log.Infof("登录成功 欢迎使用: %v", cli.Nickname)
	log.Info("开始加载好友列表...")
	global.Check(cli.ReloadFriendList(), true)
	log.Infof("共加载 %v 个好友.", len(cli.FriendList))
	log.Infof("开始加载群列表...")
	global.Check(cli.ReloadGroupList(), true)
	log.Infof("共加载 %v 个群.", len(cli.GroupList))
	if uint(base.Account.Status) >= uint(len(allowStatus)) {
		base.Account.Status = 0
	}
	cli.SetOnlineStatus(allowStatus[base.Account.Status])

	CQBot = coolq.NewQQBot(cli)
	servers.Run(CQBot)
}

func initAccount(account int64, password string) {
	accountInfo := config.Account{
		Uin:      account,  // QQ账号
		Password: password, // 密码为空时使用扫码登录
		Encrypt:  false,    // 是否开启密码加密
		Status:   0,        // 在线状态
		ReLogin: &config.Reconnect{
			Delay:    3, // 首次重连延迟, 单位秒
			MaxTimes: 3, // 重连间隔
			Interval: 0, // 最大重连次数, 0为无限制
		},
		UseSSOAddress:    false, // 是否使用服务器下发的新地址进行重连(注意,此设置可能导致在海外服务器上连接情况更差)
		AllowTempSession: true,  // 是否允许发送临时会话消息
	}
	base.Account = &accountInfo
	base.Reconnect = accountInfo.ReLogin
	base.LogLevel = "warn"
	base.LogColorful = true
	base.PostFormat = "string"
	base.LogAging = 15
	base.HeartbeatInterval = time.Second * time.Duration(5)
}

func DeviceInfo(protocol int) string {
	cfg := `{
  "display": "MIRAI.211876.001",
  "product": "mirai",
  "device": "mirai",
  "board": "mirai",
  "model": "mirai",
  "finger_print": "mamoe/mirai/mirai:10/MIRAI.200122.001/4910920:user/release-keys",
  "boot_id": "b1cc7e1c-fc9c-f512-07e2-acbdb829f00a",
  "proc_version": "Linux version 3.0.31-DLNvZxhc (android-build@xxx.xxx.xxx.xxx.com)",
  "protocol": %v,
  "imei": "597005714727425",
  "brand": "mamoe",
  "bootloader": "unknown",
  "base_band": "",
  "version": {
    "incremental": "5891938",
    "release": "10",
    "codename": "REL",
    "sdk": 29
  },
  "sim_info": "T-Mobile",
  "os_type": "android",
  "mac_address": "00:50:56:C0:00:08",
  "ip_address": [
    10,
    0,
    1,
    3
  ],
  "wifi_bssid": "00:50:56:C0:00:08",
  "wifi_ssid": "\u003cunknown ssid\u003e",
  "imsi_md5": "8ad8f0747209c932d9d2914ebf690f7e",
  "android_id": "6aa5f4f149a7c50f",
  "apn": "wifi",
  "vendor_name": "MIUI",
  "vendor_os_name": "mirai"
}`
	return fmt.Sprintf(cfg, protocol)
}

const (
	ProtocolDefault = 0 // QQ登录方式(Default/Unset)	当前版本下默认为iPad
	ProtocolAndroid = 1 // QQ登录方式(ndroid Phone)
	ProtocolWatch   = 2 // QQ登录方式(Android Watch)
	ProtocolMacOS   = 3 // QQ登录方式(MacOS)
	ProtocolQiDian  = 4 // QQ登录方式(企点)	只能登录企点账号或企点子账号
	ProtocolIPad    = 5 // QQ登录方式(iPad)
	ProtocolAPad    = 6 // QQ登录方式(aPad)
)

func qrcode() error {
	rsp, err := cli.FetchQRCodeCustomSize(1, 2, 1)
	if err != nil {
		return err
	}
	_ = os.WriteFile("qrcode.png", rsp.ImageData, 0o644)
	defer func() { _ = os.Remove("qrcode.png") }()
	if cli.Uin != 0 {
		log.Infof("请使用账号 %v 登录手机QQ扫描二维码 (qrcode.png) : ", cli.Uin)
	} else {
		log.Infof("请使用手机QQ扫描二维码 (qrcode.png) : ")
	}
	time.Sleep(time.Second)
	serveFrames(rsp.ImageData)
	printQRCode(rsp.ImageData)
	s, err := cli.QueryQRCodeStatus(rsp.Sig)
	if err != nil {
		return err
	}
	prevState := s.State
	for {
		time.Sleep(time.Second)
		s, _ = cli.QueryQRCodeStatus(rsp.Sig)
		if s == nil {
			continue
		}
		if prevState == s.State {
			continue
		}
		prevState = s.State
		switch s.State {
		case client.QRCodeCanceled:
			log.Fatalf("扫码被用户取消.")
		case client.QRCodeTimeout:
			log.Fatalf("二维码过期")
		case client.QRCodeWaitingForConfirm:
			log.Infof("扫码成功, 请在手机端确认登录.")
		case client.QRCodeConfirmed:
			res, err := cli.QRCodeLogin(s.LoginInfo)
			if err != nil {
				return err
			}
			return loginResponseProcessor(res)
		case client.QRCodeImageFetch, client.QRCodeWaitingForScan:
			// ignore
		}
	}
}

func serveFrames(imgByte []byte) {

	img, _, err := image.Decode(bytes.NewReader(imgByte))
	if err != nil {
		log.Fatalln(err)
	}

	out, _ := os.Create("./QRCode.jpeg")
	defer out.Close()

	var opts jpeg.Options
	opts.Quality = 1

	err = jpeg.Encode(out, img, &opts)
	//jpeg.Encode(out, img, nil)
	if err != nil {
		log.Println(err)
	}

	in, _ := os.Create(TmpQRCodeIMGPath)
	_, err = io.Copy(in, out)
}

const TmpQRCodeIMGPath = "./Tmp_QRCode.jpeg"

func QQMessageSend(targetQQ int64, message string) {
	CQBot.CQSendPrivateMessage(targetQQ, 0, gjson.Result{
		Type: 3,
		Str:  message,
	}, false)
}
