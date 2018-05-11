<?php
/**
 * Instagram 用户信息
 *
 * 
 */
class Instagram {

	const HTTP_TIME_OUT = 3;
	const HTTP_GET = 'GET';
	const HTTP_POST = 'POST';

	const INS_HOME_SITE = 'https://www.instagram.com';
	const INS_LOGIN_SITE = 'https://www.instagram.com/accounts/login/ajax/';
	const INS_LOGIN_USER_INFO_SITE = 'https://www.instagram.com/graphql/query/?query_hash=%s&variables=%s';

	const INS_HOSTS = 'www.instagram.com';

	const HTTP_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36';
	const HTTP_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8';

	private $isLogin = false;
	private $userName = '';
	private $userPass = '';
	private $loginUser = [];
	private $followCount = 10;

	private $httpConfig = [];

	private $insUserInfo = [
		'user_name' => '',
		'full_name' => '',
		'bio' => '',
		'avatar' => '',
		'avatar_mid' => '',
		'followers' => 0,
		'uid' => '',
	];

	private $queryHash = '';
	private $queryHash2 = '';

	private $insVariables = [
		'user_id' => '',
		'include_chaining' => true,
		'include_reel' => true,
		'include_suggested_users' => false,
		'include_logged_out_extras' => false, 
		'include_highlight_reels' => true,
	];

	const HTTP_HEADER_COOKIE_KEY = 'set-cookie';
	private $httpResponseHeaders = [];
	private $httpCookies = [];
	private $httpLoginCookies = [];
	private $postData = [];
	private $queryData = [];

	private $hasContent = false;

	private $httpCode = '';
	private $httpInfo = [];
	private $httpUrl = '';
	
	// 证书文件
	private $pemFile = '';


	// 用户正则
	// window._sharedData
	const INS_USER_INFO_REG = '/window._sharedData\s?=\s?(.+)<\/script>/';
	// "logging_page_id":"profilePage_3180916487"
	const INS_USER_PAGE_ID_REG = '/logging_page_id.+profilePage_(\d+)/';
	const INS_USER_BIO_REG = '/ProfilePage.+?biography":"(.+?)","/';
	const INS_USER_FULLNAME_REG = '/ProfilePage.+?full_name":"(.+?)","/';
	const INS_USER_PIC_REG = '/ProfilePage.+?profile_pic_url":"(.+?)","/';
	const INS_USER_PIC2_REG = '/ProfilePage.+?profile_pic_url_hd":"(.+?)","/';
	const INS_USER_NAME_REG = '/ProfilePage.+?username":"(.+?)","/';
	const INS_USER_FOLLOWED_REG = '/ProfilePage.+?edge_followed_by(.+?)count":[^\d]?(\d+)[^\d]?},"/';
	const INS_QUERY_HASH_REG = '/\/graphql\/query\/\?query_hash=(.+?)[&]/';

	// set-cookie
	const HTTP_HEADER_COOKIE_REG = '/[Ss]et-[Cc]ookie.?:.?(.+?=[^;]+?);/';




	private $insHeaders = [
		'Host' => self::INS_HOSTS,
		'Accept' => self::HTTP_ACCEPT,
		'User-agent' => self::HTTP_UA,
		'Pragma' => 'no-cache',
	];


	public function __construct($userName='', $userPass='') {
		$this->userName = $userName;
		$this->userPass = $userPass;
	}

	/**
	 * 设置登录
	 * 
	 * @param [type] $login [description]
	 */
	private function setLogin($login) {
		$this->isLogin = $login;
	}

	/**
	 * 是否登录
	 * 
	 * @return boolean [description]
	 */
	public function isLogin() {
		return $this->isLogin;
	}

	/**
	 * 设置登录名称
	 * 
	 * @param [type] $name [description]
	 */
	public function setUserName($name) {
		$this->userName = $name;
	}

	/**
	 * 设置登录密码
	 * 
	 * @param [type] $pass [description]
	 */
	public function setUserPass($pass) {
		$this->userPass = $pass;
	}

	public function getMicroTime() {
		return str_replace('.', '', microtime(true));
	}

	/**
	 * 获取查询登录用户的url
	 * 
	 * @param  [type] $hash [description]
	 * @return [type]       [description]
	 */
	public function getUserLoginQueryUrl($hash, $variables='%7B%7D') {
		$url = self::INS_LOGIN_USER_INFO_SITE;
		return sprintf($url, $hash, $variables);
	}

	/**
	 * 获取当前登录用户的信息
	 * 
	 * @return [type] [description]
	 */
	public function getLoginUser() {
		return $this->loginUser;
	}

	/**
	 * http head referer
	 * 
	 * @param [type] $referer [description]
	 */
	private function setHeaderReferer($referer) {
		$this->insHeaders['Referer'] = $referer;
	}

	/**
	 * 获取HTTP响应的头部信息
	 * 
	 * @return [type] [description]
	 */
	public function getResponseHeaders() {
		return $this->httpResponseHeaders;
	}

	/**
	 * 设置ssl 证书
	 * @param [type] $file [description]
	 */
	public function setPemFile($file) {
		$this->pemFile = $file;
	}

	/**
	 * 返回http 请求信息
	 * @return [type] [description]
	 */
	public function dumpHttpInfo() {
		$str = "url: " . $this->httpUrl. "\n";
		$str .= 'ret_code: ' . $this->httpCode . "\n";
		$str .= 'query_data: ' . var_export(array_merge($this->postData, $this->queryData), true) . "\n";
		$str .= 'http: ' . var_export($this->httpInfo, true ). "\n";
		
		
		return $str;
	}

	/**
	 * 退出登录
	 * 
	 * @return [type] [description]
	 */
	public function logout() {
		$this->loginUser = [];
		$this->isLogin = false;
		$this->httpLoginCookies = [];
		$this->httpCookies = [];

		return true;
	}

	/**
	 * 登录
	 * @return [type] [description]
	 */
	public function login($name='', $pass='') {
		if($name) {
			$this->setUserName($name);
		}
		if($pass) {
			$this->setUserPass($pass);
		}

		if(!$this->userName || !$this->userPass) {
			return false;
		}

		// 访问页面，获取cookie
		$this->viewInstagramSite();
		if(!$this->hasContent) {
			return false;
		}

		$cookies = $this->fetchHttpCookies();

		$this->httpCookies = array_merge($cookies, $this->httpCookies);


		$data = [
			'username' => $this->userName,
			'password' => $this->userPass,
			'queryParams' => '{}',
		];

		$headers = [
			// 'Content-Type' => 'application/x-www-form-urlencoded',
			'Accept' => '*/*',
			'X-Requested-With' => 'XMLHttpRequest',
			'X-CSRFToken' => $cookies['csrftoken'],
		];
		$content = $this->httpPost(self::INS_LOGIN_SITE, $data, $headers);

		$cookies1 = $this->fetchHttpCookies();

		if($content) {
			$jsonArr = @json_decode($content, true);

			if(is_array($jsonArr) && isset($jsonArr['authenticated']) && $jsonArr['authenticated'] ) {
				$this->setLogin(true);

				$this->httpLoginCookies = array_merge($cookies1, $this->httpLoginCookies);
			}

		}
		if(!$this->isLogin) {
			if(isset($cookies1['sessionid']) && !$this->likeEmptyStr($cookies1['sessionid']) ) {
				$this->setLogin(true);

				$this->httpLoginCookies = array_merge($cookies1, $this->httpLoginCookies);
			}
		}
		
		$hash = $this->getUserQueryHash();


		$this->queryUserName($hash);


		return $this->isLogin;
	}

	/**
	 * 设置获取用户粉丝的个数
	 * 
	 * @param integer $count [description]
	 */
	public function setGetUserFollowerCount($count = 10) {
		$this->followCount = $count;
	}

	/**
	 * 获取用户的关注列表
	 * 
	 * @param  [type] $userName      [description]
	 * @param  [type] $loginUserName [description]
	 * @param  [type] $loginPass     [description]
	 * @return [type]                [description]
	 */
	public function getUserFollowers($userName, $loginUserName, $loginPass) {
		$hasLogin = $this->login($loginUserName, $loginPass);
		if(!$hasLogin || ! $userName) {
			return false;
		}

		// 个人页
		$url = $this->getUserProfileSite($userName);

		$contents = $this->httpRequest($url);
		if(!$contents) {
			return false;
		}

		$userInfo = $this->fetchUserInfo($contents);

		if(!$userInfo['uid']) {
			return false;
		}

		$variables = $this->insVariables;
		$variables['user_id'] = $userInfo['uid'];
		$uname = $userInfo['user_name'];

		$queryUrl = $this->getUserLoginQueryUrl($this->queryHash2, urlencode(json_encode($variables)));


		$queryInfo = $this->httpRequest($queryUrl);
		var_dump($queryUrl, $queryInfo);
	}


	/**
	 * 获取查询当前登录用户的hash
	 * 
	 * @return [type] [description]
	 */
	public function getUserQueryHash() {
		$contents = $this->viewInstagramSite();
		$cookies = $this->fetchHttpCookies();

		$hash = $this->regMatchIndex(self::INS_QUERY_HASH_REG, $contents, 1);
		
		if(!$hash) {
			return '';
		}

		$this->queryHash = $hash;
		$this->queryHash2 = $this->regMatchIndex(self::INS_QUERY_HASH_REG, $contents, 1, 1);
		$this->httpCookies = array_merge($cookies, $this->httpCookies);

		return $hash;
	}

	/**
	 * 查询当前登录用户信息
	 * 
	 * @param  [type] $hash [description]
	 * @return [type]       [description]
	 */
	public function queryUserName($hash) {
		if(!$this->isLogin) {
			return [];
		}

		if(!$hash) {
			return [];
		}

		if(!empty($this->loginUser)) {
			return $this->loginUser;
		}


		$url = $this->getUserLoginQueryUrl($hash);
		$contents = $this->httpRequest($url);

		if($contents) {
			$jsonArr = @json_decode($contents, true);
			if(is_array($jsonArr) && isset($jsonArr['data']) && isset($jsonArr['data']['user'])) {
				$id = $jsonArr['data']['user']['id'];
				$uname = $jsonArr['data']['user']['username'];

				$this->loginUser = [
					'id' => $id, 
					'user_name' => $uname,
				];
			}

		}

		return $this->loginUser;
	}

	/**
	 * 查看Instagram 主页
	 * 
	 * @return [type] [description]
	 */
	public function viewInstagramSite() {
		return $this->httpRequest(self::INS_HOME_SITE);
	}

	/**
	 * 获取用户信息
	 * 
	 * @param  [type] $userName [description]
	 * @return [type]           [description]
	 */
	public function getUserInfo($userName, $method=self::HTTP_GET) {
		$userSite = $this->getUserProfileSite($userName);

		$this->httpInit(['method' => $method]);
		$contents = $this->httpRequest($userSite,$method, [], []);

		return $this->fetchUserInfo($contents);
	}


	/**
	 * 获取用户信息
	 * 
	 * @param  string $contents [description]
	 * @return [type]           [description]
	 */
	public function fetchUserInfo($contents='') {
		$insUserInfo = [];
		if(!$contents) {
			return $insUserInfo;
		}
		$isTest = preg_match_all(self::INS_USER_INFO_REG, $contents, $matches);

		if(!$isTest || !isset($matches[1])) {
			return $insUserInfo;
		}

		$jsonContent = $matches[1][0];
		unset($matches);

		$pageId = $this->regMatchIndex(self::INS_USER_PAGE_ID_REG, $jsonContent, 1);
		if(!$pageId) {
			return $insUserInfo;
		}

		$bio = $this->regMatchIndex(self::INS_USER_BIO_REG, $jsonContent, 1);

		$fullName = $this->regMatchIndex(self::INS_USER_FULLNAME_REG, $jsonContent, 1);

		$uname = $this->regMatchIndex(self::INS_USER_NAME_REG, $jsonContent, 1);

		$pic = $this->regMatchIndex(self::INS_USER_PIC_REG, $jsonContent, 1);

		$bigPic = $this->regMatchIndex(self::INS_USER_PIC2_REG, $jsonContent, 1);

		$followers = $this->regMatchIndex(self::INS_USER_FOLLOWED_REG, $jsonContent, 2);

		$insUserInfo['uid'] = strval($pageId);
		$insUserInfo['user_name'] = strval($uname);
		$insUserInfo['full_name'] = strval($fullName);
		$insUserInfo['bio'] = strval($bio);
		$insUserInfo['avatar'] = strval($pic);
		$insUserInfo['avatar_mid'] = strval($bigPic);
		$insUserInfo['followers'] = intval($followers);

		$this->insUserInfo = array_merge($this->insUserInfo, $insUserInfo);

		return $this->insUserInfo;
	}

	/**
	 * 正则匹配的内容
	 * 
	 * @param  [type] $reg      [description]
	 * @param  [type] $contents [description]
	 * @param  [type] $index    [description]
	 * @return [type]           [description]
	 */
	private function regMatchIndex($reg, $contents, $index, $index2=0) {
		$matches = [];
		$isTest = preg_match_all($reg, $contents, $matches);

		if(!$isTest || !isset($matches[$index])) {
			return false;
		}

		if(!is_array($matches[$index])) {
			return $matches[$index];
		}
		if(!$index2) {
			return array_shift($matches[$index]);
		}
		if(isset($matches[$index][$index2])) {
			return $matches[$index][$index2];
		}

		return false;
	}

	/**
	 * Instagram 用户主页url
	 * 
	 * @param  [type] $userName [description]
	 * @return [type]           [description]
	 */
	public function getUserProfileSite($userName) {
		return sprintf(self::INS_HOME_SITE ."/%s/", $userName);
	}

	/**
	 * http 配置 初始化
	 * 
	 * @param  array  $data [description]
	 * @return [type]       [description]
	 */
	public function httpInit($data=[]) {
		if(isset($data['method'])) {
			$this->httpConfig['method'] = $data['method'];
		}

		if(isset($data['timeout'])) {
			$this->httpConfig['timeout'] = $data['timeout'];
		}

		if(isset($data['referer'])) {
			$this->httpConfig['referer'] = $data['referer'];
			$this->insHeaders['Referer'] = $data['referer'];
		}

		if(isset($data['is_ssl'])) {
			$this->httpConfig['is_ssl'] = $data['is_ssl'];
		}

		if(isset($data['data'])) {
			$this->httpConfig['data'] = $data['data'];
		}

		if(isset($data['header'])) {
			$this->httpConfig['header'] = $data['header'];
		}

	}

	/**
	 * HTTP GET
	 * 
	 * @param  [type] $url     [description]
	 * @param  array  $data    [description]
	 * @param  array  $headers [description]
	 * @return [type]          [description]
	 */
	public function httpGet($url, $data=[], $headers=[]) {
		return $this->httpRequest($url, self::HTTP_GET, $data, $headers);
	}

	/**
	 * HTTP POST
	 * 
	 * @param  [type] $url     [description]
	 * @param  array  $data    [description]
	 * @param  array  $headers [description]
	 * @return [type]          [description]
	 */
	public function httpPost($url, $data=[], $headers=[]) {
		return $this->httpRequest($url, self::HTTP_POST, $data, $headers);
	}


	/**
	 * http 头部cookie
	 * 
	 * @return [type] [description]
	 */
	public function fetchHttpCookies() {
		$cookies = [];
		$headers = $this->getResponseHeaders();

		if(empty($headers)) {
			return $cookies;
		}
		foreach($headers as $k => $v) {
			if(stripos($v, self::HTTP_HEADER_COOKIE_KEY) !== false) {
				$kv = $this->regMatchIndex(self::HTTP_HEADER_COOKIE_REG, $v, 1);
				if($kv) {
					$kv = trim($kv);
					$kvInfo = explode('=', $kv);

					$_k = trim($kvInfo[0]);
					$_v = !isset($kvInfo[1]) ? '' : trim($kvInfo[1]);

					if(isset($cookies[$_k]) ) {
						if($_v && !empty($cookies[$_k]) && !$this->likeEmptyStr($_v) ) {
							$cookies[$_k] = $_v;
						}
						
					} else {
						$cookies[$_k] = $_v;
					}
				}
			}
		}

		return $cookies;
	}

	private function canHttpConfig($defaultValue, $key) {
		if($defaultValue) {
			return $defaultValue;
		}

		if(isset($this->httpConfig[$key]) && $this->httpConfig[$key]) {
			return $this->httpConfig[$key];
		}

		if(strtolower($key) == 'timeout') {
			return self::HTTP_TIME_OUT;
		}

		if(strtolower($key) == 'method') {
			return self::HTTP_GET;
		}

	}

	private function likeEmptyStr($str) {
		if(!$str) {
			return true;
		}
		$is = preg_match_all('/["\'](\s*?)["\']/', $str, $matches);

		return $is ? true : false;
	}

	/**
	 * http 请求
	 * 
	 * @param  [type]  $url     [description]
	 * @param  [type]  $method  [description]
	 * @param  array   $data    [description]
	 * @param  array   $headers [description]
	 * @param  integer $timeout [description]
	 * @return [type]           [description]
	 */
	public function httpRequest($url, $method='', $data=[], $headers=[], $timeout=0) {
		$content = '';
		$method = $this->canHttpConfig($method, 'method');
		$timeout = $this->canHttpConfig($method, 'timeout');

		$data = (!isset($this->httpConfig['data']) || empty($this->httpConfig['data'])) ? $data : array_merge($data, $this->httpConfig['data']);
		$headers = (!isset($this->httpConfig['header']) || empty($this->httpConfig['header'])) ? $headers : array_merge($headers, $this->httpConfig['header']);

		$headers = array_merge($headers, $this->insHeaders);

		if(function_exists('curl_init')) {
			$content = $this->curlHttp($url, $method, $data, $headers, $timeout);
		} else {
			$content = $this->fileHttp($url, $method, $data, $headers, $timeout);
		}

		if($content) {
			$this->hasContent = true;
		}

		return $content;
	}

	/**
	 * curl 请求http
	 * 
	 * @param  [type]  $url     [description]
	 * @param  [type]  $method  [description]
	 * @param  array   $data    [description]
	 * @param  array   $headers [description]
	 * @param  integer $timeout [description]
	 * @return [type]           [description]
	 */
	private function curlHttp($url, $method='', $data=[], $headers=[], $timeout=0) {
		if(!$timeout) {
			$timeout = self::HTTP_TIME_OUT;
		}
		if(!$method) {
			$method = self::HTTP_GET;
		}
		$method = strtoupper($method);
		if(!function_exists('curl_init')) {
			return false;
		}

		$isSSl = false;
		if(isset($this->httpConfig['is_ssl']) || !empty($this->pemFile)) {
			$isSSl = $this->httpConfig['is_ssl'];
		}
		$isPost = false;
		if(strtoupper($method) == self::HTTP_POST) {
			$isPost = true;
		}

		$ch = curl_init();
		
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		curl_setopt($ch, CURLOPT_USERAGENT, self::HTTP_UA);
		if(!$isSSl) {
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		} else {
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
			curl_setopt($ch,CURLOPT_CAINFO, $this->pemFile);
		}
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, self::HTTP_TIME_OUT);
		curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		switch ($method) {  
			case self::HTTP_POST:  
				curl_setopt($ch, CURLOPT_POST, true);  
				if (!empty($data)) {  
					curl_setopt($ch, CURLOPT_POSTFIELDS, $data);  
					$this->postData = $data;  
				}
				break;  
			default:  
				if (!empty($data)) {  
					$sep = '?';
					if(strpos($url, '?') !== false) {
						$sep ='&';
					}
					$url = $url . $sep . http_build_query($data);
				}
		} 

		curl_setopt($ch, CURLOPT_URL, $url );  
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->buildHttpPlainHeader($headers) );  
        curl_setopt($ch, CURLOPT_HEADER, TRUE ); 
        curl_setopt($ch, CURLINFO_HEADER_OUT, TRUE ); 
        curl_setopt($ch, CURLOPT_COOKIE, $this->buildHttpCookie());
       

        $response = curl_exec($ch);  
        $this->httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);  
        $this->httpInfo = array_merge($this->httpInfo, curl_getinfo($ch));  
        $this->httpUrl = $url;

        // 
        

        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
		$header = substr($response, 0, $headerSize);
		$body = substr($response, $headerSize);
		$this->httpResponseHeaders = explode("\r\n", $header);


		
		curl_close($ch); 
        return $body;

	}

	public function buildHttpCookie($cookies=[]) {
		$cookies = array_merge($cookies, $this->httpCookies, $this->httpLoginCookies);
		
		if(empty($cookies)) {
			return '';
		}

		$tmp = [];
		foreach($cookies as $k => $v) {
			$tmp[] = "{$k}={$v}";
		}
		if(empty($tmp)) {
			return '';
		}

		return implode(";", $tmp);
	}


	/**
	 * http 头部
	 * 
	 * @param  [type] $headers [description]
	 * @return [type]          [description]
	 */
	private function buildHttpPlainHeader($headers) {
		$headerList = [];
		

		foreach($headers as $k => $v) {
			if(is_numeric($k)) {
				$headerList[] = trim($v);
			} else {
				$k = ucfirst($k);
				$headerList[] = trim($k . ': '. $v );
			}
		}
		return $headerList;
	}

	/**
	 * 获取链接内容
	 * 
	 * file_get_contents 
	 * 
	 * @param  [type]  $url     [description]
	 * @param  [type]  $method  [description]
	 * @param  array   $data    [description]
	 * @param  array   $headers [description]
	 * @param  integer $timeout [description]
	 * @return [type]           [description]
	 */
	public function fileHttp($url, $method='', $data=[], $headers=[], $timeout=0) {
		if(!$timeout) {
			$timeout = self::HTTP_TIME_OUT;
		}
		if(!$method) {
			$method = self::HTTP_GET;
		}

		$method = strtoupper($method);
		$opts = array(
			'http' => array(
				'method'=> $method,
				'timeout' => $timeout,
				'header'=> implode("\r\n", $this->buildHttpPlainHeader($headers))."\r\n",
				'context' => '',
				'ignore_errors' => true,
				'cookie' => $this->buildHttpCookie(),
			)
		);
		if(!empty($data)) {
			if(!is_array($data)) {
				$data = [$data];
			}
			if($method == self::HTTP_GET) {
				$opts['http']['context'] = http_build_query($data, '', '&');
			} else {
				$opts['http']['context'] = http_build_query($data);
			}
		}

		$this->httpUrl = $url;
		$context = stream_context_create($opts);
		$file = file_get_contents($url, false, $context);

		$this->httpResponseHeaders = !isset($http_response_header) ? [] : $http_response_header;

		return $file;
	}


}