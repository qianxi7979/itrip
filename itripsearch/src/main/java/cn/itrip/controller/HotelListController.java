package cn.itrip.controller;

import cn.itrip.beans.dtos.Dto;
import cn.itrip.beans.vo.hotel.ItripHotelVO;
import cn.itrip.beans.vo.hotel.SearchHotCityVO;
import cn.itrip.beans.vo.hotel.SearchHotelVO;
import cn.itrip.common.DtoUtil;
import cn.itrip.common.EmptyUtils;
import cn.itrip.common.Page;
import cn.itrip.service.SearchHotelService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by zezhong.shang on 17-5-10.
 */
@Controller
@Api(value = "API", basePath = "/http://api.itrap.com/api")
@RequestMapping(value = "/api/hotellist")
public class HotelListController {

    @Resource
    private SearchHotelService searchHotelService;

    /***
     * 搜索酒店分页
     * @param vo
     * @param pageSize
     * @param pageNo
     * @return
     * @throws Exception
     */
    @ApiOperation(value = "查询酒店分页", httpMethod = "POST",
            protocols = "HTTP",produces = "application/json",
            response = Dto.class,notes = "查询酒店分页(用于查询酒店列表)"+
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码: </p>"+
            "<p>0003: 系统异常,获取失败</p>")
    @RequestMapping(value = "/searchItripHotelPage",produces = "application/json",method = RequestMethod.POST)
    @ResponseBody
    public Dto<Page<ItripHotelVO>> searchItripHotelPage(@RequestBody SearchHotelVO vo){
        Page page= null;
        if(EmptyUtils.isEmpty(vo) || EmptyUtils.isEmpty(vo.getDestination())){
            return  DtoUtil.returnFail("目的地不能为空","0002");
        }
        try {
            page = searchHotelService.searchItripHotelPage(vo, vo.getPageNo(),vo.getPageSize());
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("系统异常", "0003");
        }
        return DtoUtil.returnDataSuccess(page);
    }

    @ApiOperation(value = "根据热门城市查询酒店", httpMethod = "POST",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class,notes = "根据热门城市查询酒店"+
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码: </p>"+
            "<p>0003: 系统异常,获取失败</p>")
    @RequestMapping(value = "/searchItripHotelListByHotCity",produces = "application/json", method = RequestMethod.POST)
    @ResponseBody
    public Dto<Page<ItripHotelVO>> searchItripHotelListByHotCity(@RequestBody SearchHotCityVO vo)throws Exception{
        if(EmptyUtils.isEmpty(vo) || EmptyUtils.isEmpty(vo.getCityId())){
            return  DtoUtil.returnFail("城市id不能为空","0002");
        }
        Map<String,Object> param=new HashMap<>();
        param.put("cityId", vo.getCityId());
        List list=searchHotelService.searchItripHotelListByHotCity(vo.getCityId(),vo.getCount());
        return DtoUtil.returnDataSuccess(list);
    }

}
